#!/usr/bin/env python3
import sys
import os
from pathlib import Path
import csv
from statistics import mean
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
import traceback
from contextlib import contextmanager
import parse
import elastic_tools
from distutils.util import strtobool
from uuid import uuid4
import json


output_dir_tpl = "{mode}-{proto}-{payload_size}-{num_threads}-{num_connections}-{tls_mode}"
nginx_out_tpl = "XLIO INFO   : Number of Nginx workers{workers:>d}"
exit_code = 0
# pr_id = os.environ.get("CHANGE_ID")  # get Github PR ID from Jenkins Pull Request Builder plugin
pr_id = os.environ.get("ghprbPullId", os.environ.get("PR_ID"))  # get Github PR ID from Jenkins Pull Request Builder plugin
# source_branch = os.environ.get("ghprbSourceBranch")
set_as_baseline = os.environ.get("SET_AS_BASELINE", "false")
set_as_baseline = strtobool(set_as_baseline) == 1  # converting string value from Jenkins to bool
dashboard_url = "http://r-elk.mtr.labs.mlnx/s/xlio/app/visualize#/edit/{dashboard_id}?_a=(query:(language:kuery,query:'{query}'))"
dashboards = {
    "rps": {
        "88c498f0-484d-11ec-bf01-8162e9e81821": ("RPS per payload", "type:rps and (benchmark_id:{benchmark_id} or is_baseline:true)"),
    },
    "cps": {
        "cb5284f0-8ef4-11ec-8824-7f026d149a00": ("CPS per payload", "type:cps and (benchmark_id:{benchmark_id} or is_baseline:true)"),
    },
}
benchmark_id = str(uuid4())
benchmark_ids_file = Path(sys.argv[0]).parent / "../reports" / "report_ids.txt"


class TemplateMatchException(Exception):
    pass


def search(template, text):
    res = parse.search(template, text)
    if res:
        return res.named
    else:
        raise TemplateMatchException(f"String '{text}' doesn't match template '{template}'")

def dehumanize(size_str):
    units = {
        "KB": 1000,
        "MB": 1000 ** 2,
        "GB": 1000 ** 3,
        "B":  1,
    }
    size_str = size_str.upper()
    for u in units.keys():
        if size_str.endswith(u):
            return int(size_str.replace(u, "")) * units[u]


def find_first(path, glob_pattern):
    return list(path.glob(glob_pattern))[0]


@contextmanager
def open_and_handle_errors(directory, glob_pattern):
    global exit_code
    try:
        path = find_first(directory, glob_pattern)
        assert path is not None, f"Cannot find a file matching {directory}/{glob_pattern}"
        assert path.stat().st_size > 0, "File should not be empty"
        yield open(path)
    except Exception as e:
        print(f"Error while processing {directory}/{glob_pattern}: {e}")
        traceback.print_tb(e.__traceback__)
        exit_code = 1


def process_dir(run_id, output_dir):
    global exit_code
    try:
        settings = search(output_dir_tpl, output_dir.name)

        wrk_data = []
        for json_file in output_dir.glob("**/client*/wrk.out.json"):
            print(f"Loading {json_file}")
            wrk_data.append(json.load(open(json_file))["json_report"])
        print(f"wrk_data={wrk_data}")
        if not wrk_data:
            print(f"Cannot load any data from wrk.out.json files in {output_dir}")
            sys.exit(1)

        wrk_sum = {}
        for key in ["requests", "bytes"]:
            wrk_sum[key] = sum([d[key] for d in wrk_data])
        duration = wrk_data[0]["duration"] / 1_000_000
        rps = round(wrk_sum["requests"] / duration, 2)
        gigabits = wrk_sum["bytes"] * 8 / 1000 ** 3
        throughput = round(gigabits / duration, 3)

        with open_and_handle_errors(output_dir, "**/*server*/nginx_num_workers") as nginx_file:
            nginx_data = {"workers": int(nginx_file.read().strip())}

        with open_and_handle_errors(output_dir, "**/*server*/*.nmon") as nmon_file:
            nmon_data = {}
            samples_idle = []
            for row in csv.reader(nmon_file):
                if row[0] == "AAA" and row[1] == "cpus":
                    nmon_data["cpus"] = int(row[2])
                if row[0] == "CPU_ALL" and row[1].startswith("T"):
                    samples_idle.append(float(row[5]))
            nmon_data["cpu_usage"] = round(mean([100 - s for s in samples_idle[10:]]), 3)

        print(f"Processed directory {output_dir}, run ID {run_id}, results: RPS={rps}, throughput={throughput} Gbit/s")

        with open("/proc/cpuinfo") as cpuinfo:
            for line in cpuinfo:
                if line.startswith("cpu MHz"):
                    mhz = int(float(line.split()[-1]))

        cpu_cycles_per_req = mhz * 10 ** 6 * nginx_data["workers"] * nmon_data["cpu_usage"] / 100 / rps

        created_at = datetime.fromtimestamp(output_dir.stat().st_ctime)
        return {
            "benchmark_id": benchmark_id,  # common ID of several shapshots (one benchmark run)
            "snapshot_id": str(uuid4()),  # unique ID of this shapshot
            "created_at": created_at,
            "ID": f"{run_id}-{created_at}",
            "mode": settings["mode"],
            "Proto(http/https)": settings["proto"],
            "Workers": nginx_data["workers"],
            "Payload": settings["payload_size"],
            "payload_bytes": dehumanize(settings["payload_size"]),
            "Throughput(Gbps)": throughput,
            "Rate(RPS)": rps,
            "CPU(%)": nmon_data["cpu_usage"],
            "CPUs": nmon_data["cpus"],
            "cpu_freq": mhz,
            "cpu_cycles_per_req": cpu_cycles_per_req,
            # "nmon_data": nmon_data,
            "run_id": str(run_id),
            "title": f"pr{pr_id}_run{run_id}_{settings['proto']}_{settings['mode']}_{nginx_data['workers']}_{settings['payload_size']}",
            "branch": pr_id,
            "is_baseline": set_as_baseline,
            "is_head": False,
            "duration": round(duration),
        }
    except Exception as e:
        print(f"Error while processing {output_dir}: {e}")
        traceback.print_tb(e.__traceback__)
        exit_code = 1


def get_dirs_from_args(args):
    args = [Path(a) for a in args]
    # select directories which match "output_dir_tpl" pattern:
    dirs = [a for a in args if a.is_dir() and search(output_dir_tpl, a.name)]
    # sort by directory create time:
    return sorted(dirs, key=lambda d: d.stat().st_ctime)


def process_dirs_in_parallel(dirs):
    return list(ProcessPoolExecutor().map(process_dir, *zip(*enumerate(dirs, start=1))))


def create_html_report(bulk_type):
    output_dir = Path(sys.argv[0]).parent / "../reports"
    output_dir.mkdir(exist_ok=True)
    links = []
    for dashboard_id, data in dashboards[bulk_type].items():
        title, query = data
        link = dashboard_url.format(
            dashboard_id=dashboard_id,
            query=query.format(benchmark_id=benchmark_id)
        )
        links.append(f"""<a target=_blank href="{link}">{title}</a>""")

    links_html = "</li><li>".join(links)
    html_content = f"""<!doctype html>
    <html>
    <head>
        <title>Performance benchmark result</title>
    </head>
    <body>
        <p><ul><li>{links_html}</li></ul></p>
    </body>
    </html>"""
    with open(output_dir / f"{bulk_type}.html", "w") as html_file:
        html_file.write(html_content)


def save_benchmark_id():
    print(f"Saving {benchmark_id=} to {benchmark_ids_file}")
    with open(benchmark_ids_file, "a") as f:
        f.write(benchmark_id + "\n")


if __name__ == "__main__":
    bulk_type = sys.argv[1].lower()
    assert bulk_type in ("cps", "rps"), "First argument 'bulk_type' should be one of: cps, rps"
    dirs = get_dirs_from_args(sys.argv[2:])
    data = process_dirs_in_parallel(dirs)
    # filter out empty values:
    data = list(filter(None, data))
    for d in data:
        d["type"] = bulk_type

    if data:
        if set_as_baseline:
            if exit_code == 0:
                for mode in set([d["mode"] for d in data]):
                    print(f"Removing previous baseline value for {bulk_type=} and {mode=}")
                    elastic_tools.remove_baseline(bulk_type, mode)
            else:
                print("Won't set new baseline value, because there are failed runs")

        print("Submitting data to Elastic")
        for d in data:
            elastic_tools.export_snapshot(d["created_at"].strftime("%Y-%m-%d_%H:%M:%S"), d)

        create_html_report(bulk_type)
        save_benchmark_id()

        print("Done")

    sys.exit(exit_code)
