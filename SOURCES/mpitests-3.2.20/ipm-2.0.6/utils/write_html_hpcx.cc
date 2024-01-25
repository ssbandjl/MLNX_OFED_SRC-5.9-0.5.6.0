#ifdef HPCX_IPM_PARSER
#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "write_html.h"

// taken from perl version of ipm_parse
static char const *ipm_colors[] = {
  "red", "green", "blue", "yellow",
  "purple","coral", "orange", "darkblue", "limegreen",
  "skyblue","claret", "teal", "magenta", "brightblue",
  "black", "lightpurple", "kelleygreen", "yellowgreen",
  "redorange", "darkblue", "tan1", "drabgreen",
  "yellow2", "teal", "lavender",
  "rgb(0.0,1.0,1.0)","rgb(0.8,0.8,0.8)",
  "rgb(0.7,0.7,0.7)","rgb(0.6,0.6,0.6)",
  "rgb(0.5,0.5,0.5)", "rgb(0.2,0.2,0.2)"
};

void write_host_list(FILE*f, job_t* job, banner_t *b);
void write_header(FILE*f, job_t* job, banner_t *b);
void write_footer(FILE*f);
void write_mpi_funcs_size(FILE *f, job_t* job, ploticus_t& plot);
void write_computation(FILE* f, job_t *job);
void write_mpi_allranks(FILE* f, job_t *job, banner_t *b, ploticus_t& plot);
void write_mpi_distrib_size(FILE* f, job_t *job, banner_t *b);
void write_mpi_perproc_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& plot);
void write_timings(FILE *f, job_t* job, banner_t *data, ploticus_t& plot);
void write_size_distrib_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& plot);
void write_p2p_matrix( FILE *f, job_t* job, banner_t *b, ploticus_t& plot );
void write_memusage_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& plot);

class times {
public:
    unsigned long long  size;
    unsigned long long  count;
    double              ttotal;
    double              tmin;
    double              tmax;
    int                 funcId;
    int                 comm_size;
};

class compare {
public:
    bool operator() (const times &left, const times &right) {
        // descending order
        return left.ttotal > right.ttotal;
    }
} time_compare;

void write_html_hpcx( job_t* job, banner_t *b )
{
  FILE* f;
  string fname;
  ploticus_t  plot;

  job->set_result_dir();
  job->create_funcnames();

  fname = job->result_dir();
  if ( !fname.empty() ) {
    fname += "/";
  }
  if ( job->outfile == stdout ) {
    fname += "index.html";
  } else {
   fname += job->outname;
  }

  f = fopen(fname.c_str(), "w");
  if( f == NULL )  {
    fprintf(stderr, "Can't open output file '%s'\n", fname.c_str());
    exit (-1);
  }

  write_header(f, job, b);

  fprintf(f, "<table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n""<tr width=100%%>\n");
    write_computation(f, job);
    write_mpi_allranks(f, job, b, plot);
  fprintf(f, "</tr>\n</table>\n");

  write_mpi_distrib_size(f, job, b);
  write_size_distrib_graph(f, job, b, plot);
  write_timings(f, job, b, plot);
  write_mpi_perproc_graph(f, job, b, plot);

  write_p2p_matrix(f, job, b, plot);
  write_memusage_graph(f, job, b, plot);

  write_host_list(f, job, b);

  write_footer(f);

  fclose(f);
}


#define COLUMNS(one, two, three, four) fprintf(f, \
 "<tr> \
 <td width=50%%> \
 <table width=100%%> <tr> \
   <td width=50%% align=left> %s: </td> <td width=50%% align=right> %s </td> \
   </tr> \
 </table> \
 </td> \
 <td width=50%%> \
 <table width=100%%> <tr> \
   <td width=50%% align=left> %s: </td> <td width=50%% align=right> %s </td> \
   </tr> \
 </table> \
 </td> \
 </tr>", one, two, three, four);

void write_header(FILE *f, job_t *job, banner_t *data)
{
  char tmpstr[128];

  fprintf(f,
  "<html>\n \
  <title> IPM profile for %d </title> \
  <head> \
  <STYLE TYPE=\"text/css\"> \
  #unreadable { font-size: 1pt; } \
  .example { font-family: Garamond, Times, serif; } \
  </STYLE> \
  </head> \
  <body>\n \
  <table border=1 borderwidth=0 width=100%% cellpadding=0 cellspacing=0>",
  job->jobid);

  fprintf(f,
  "<tr><td width=25%% valign=\"top\" align=\"left\" bgcolor=\"lightblue\"> \
  <table  border=0 borderwidth=0 width=100%% cellpadding=0 cellspacing=0> \
    <tr><td width=\"100%%\" height=\"100%%\" valign=\"top\" align=\"left\" bgcolor=\"lightblue\"> \
    <a name=\"top\"> \
    <b> %d </b><br> \
    </a> \
    </td></tr> \
    <tr><td width=100%% valign=\"top\" align=\"left\" bgcolor=\"lightblue\"> \
    <font size=-2> \
    <ul> \
    <li> <a href=\"#lb\">Load Balance</a> \
    <li> <a href=\"#cb\">Communication Balance</a> \
    <li> <a href=\"#bs\">Message Buffer Sizes</a> \
    <li> <a href=\"#ct\">Communication Topology</a> \
    <li> <a href=\"#mu\">Memmory Usage</a> \
    <li> <a href=\"#hl\">Host List</a>  \
    </ul> \
    </font> \
    </td></tr> \
    <br><br> \
    <tr><td width=100%% valign=\"bottom\" align=\"left\" bgcolor=\"lightblue\"> \
    <center> \
    <a href=\"http://ipm-hpc.sf.net/\">Powered by IPM</a> \
    </center> \
    </td></tr> \
  </table> \
  </td>", job->jobid
  );

  fprintf(f,
  "<td width=75%% valign=\"top\"> \
  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0> \
  <tr> \
  <td width=100%% colspan=2 bgcolor=\"lightblue\" valign=\"top\">  \
  command: %s \
  </td>\
  </tr>", CMDPATH(job)
  );

  char mem[128];
  char flops[128];
  char tasks[32];
  char time[32];
  char comm[32];
  sprintf(mem,   "%.1f gbytes", data->procmem.dsum);
  sprintf(flops, "%.0f ", data->app.gflops.dsum);
  sprintf(tasks, "%d on %d hosts", data->ntasks, data->nhosts);
  sprintf(time,  "%.3f s", data->app.wallt.dmax);
  sprintf(comm,  "%.2f%%", 100.0*data->app.mpi.dsum/data->app.wallt.dsum);

  COLUMNS("codename", CODENAME(job), "state", STATE(job));
  COLUMNS("username", USERNAME(job), "group", GROUP(job));
  COLUMNS("host", HOST(job), "mpi_tasks", tasks);
  COLUMNS("start", START(job), "wallclock", time);
  COLUMNS("stop", STOP(job), "%comm", comm);
  COLUMNS("total memory", mem, "total GFlops", flops);
  COLUMNS("switch(send)", "N/A", "switch(recv)", "N/A");

  fprintf(f, "</table>\n");
  fprintf(f, "</table>\n");
}

void write_footer(FILE *f)
{
  fprintf(f, "</table>\n");
  fprintf(f, "</body>\n");
  fprintf(f, "</html>\n");
}

void write_computation( FILE *f, job_t* job)
{
  // We do not have Computation at the moment
  fprintf(f,
    "<td width=50%% valign=top>\n"
    "<table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "<tr>\n"
    "<th valign=top colspan=3 bgcolor=\"lightblue\"> <H3> Computation </H3> </th> </tr>\n"
    "<tr>\n"
    "<th valign=top bgcolor=\"lightblue\"> Event </th>\n"
    "<th valign=top bgcolor=\"lightblue\"> Count </th>\n"
    "<th valign=top bgcolor=\"lightblue\"> Pop </th>\n"
    "</tr>\n"
    "</table>\n"
    "</td>\n"
  );
}

void write_pie_ploticus_header(FILE* plot)
{
  fprintf(plot, "#proc page\n  pagesize 10 8\n\n"
    "#proc areadef\n"
    "    rectangle: 0 0 2.5 2\n"
    "    xrange: 0 1\n"
    "    yrange: 0 1\n"
    "\n"
    "#proc getdata\n"
    "data:\n"
  );
}

void write_pie_ploticus_footer(FILE* plot)
{
  fprintf(plot,
    "\n#proc pie\n"
    " firstslice: 0\n"
    " datafield: 2\n"
    " labelfield: 1\n"
    " exactcolorfield: 3\n"
    " center: 0.5(s) 0.6(s)\n"
    " radius: 0.4(s)\n"
    "\n"
    "#proc legend\n"
    " location: 1.1(s) 1.2(s)\n"
  );

}

void create_sort_times(job_t *job, vector<times> &arr)
{
  times tm;
  for (std::map<std::pair<comm_buffSize_t,int>, funcdata_t>::iterator it=job->func_list.begin();
    it!=job->func_list.end(); ++it) {
      tm.comm_size = it->first.first.first;  // Communicator size
      tm.size   = it->first.first.second;    // Buffer Size (or message size)
      tm.funcId = it->first.second;
      tm.ttotal = it->second.time;
      tm.tmin   = it->second.tmin;
      tm.tmax   = it->second.tmax;
      tm.count  = it->second.count;
      arr.push_back(tm);
  }

  // sort the array based on TTotal - descending
  std::sort(arr.begin(), arr.end(), time_compare);
}

void write_mpi_allranks( FILE *f, job_t* job, banner_t *data, ploticus_t& pl)
{
  int    i     = 0;
  int    res   = 0;
  int    count = 1;
  double mtime = 0.0;
  double wtime = 0.0;
  double mproc = 0.0;
  char   buf[8];
  const char * func  = NULL;

  std::stringstream ss;

  vector<times>     arr;

  FILE *plot = NULL;

  plot = pl.open_plot(job->result_dir(), "mpi_pie");
  if ( plot == NULL ) {
    return;
  }

  times tm;
  for ( map<int, funcdata_t>::iterator it=job->funcs.begin();
      it!=job->funcs.end(); ++it) {
    tm.funcId = it->first;
    tm.ttotal = it->second.time;
    arr.push_back(tm);
  }
  // sort the array based on TTotal - descending
  sort(arr.begin(), arr.end(), time_compare);

  wtime = data->app.wallt.dsum;
  mtime = data->app.mpi.dsum;

  write_pie_ploticus_header(plot);

  ss << "<tr>\n<th align=left bgcolor=lightblue> Func Name </th>\n";
  ss << "<th align=left bgcolor=lightblue><center>MPI %</center></th>\n</tr>";
  for ( vector<times>::iterator it=arr.begin(); it!=arr.end(); it++) {
    mproc = (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime;
    func  = job->funcnames[it->funcId].c_str();
    sprintf(buf, "%6.2f", mproc);
    ss <<  "<tr>\n<td align=left>" << func << "</td>\n<td align=right>" << buf << "</td>\n</tr>\n";
    fprintf(plot, "%s %f %s %s\n", func, mproc, ipm_colors[i++], func);
    if ( i == 13 ) break; // there is no reason to show invisible sectors - 13 functions is enough
  }
  write_pie_ploticus_footer(plot);
  fclose(plot);

  res = pl.create_graph(job->result_dir(), "mpi_pie");

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "<table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "<tr> <th bgcolor=\"lightblue\" colspan=\"2\"> <H3> Communication </H3> </th> </tr>\n"
    "<tr> <th bgcolor=\"lightblue\" colspan=\"2\"> %% of MPI Time </th> </tr>\n"
  );
  if ( res == 0 ) {
    fprintf(f, "<tr><td><center><img src=\"img/mpi_pie.png\"></center></td></tr>\n");
  } else {
    // Could not execute ploticus command.
    fprintf(f, "%s\n", ss.str().c_str());
  }
  fprintf(f, "</table>\n</td>\n");

}

void write_mpi_distrib_size(FILE *f, job_t* job, banner_t *data)
{
  char   *ptr  = NULL;
  double  time = 0.0;
  double wtime = 0.0;
  double mtime = 0.0;
  float  mproc = 0.0;
  float  wproc = 0.0;
  float  avg   = 0.0;
  float  thresh = 0.05;
  int    count = 1;
  int    max_nfuncs = MPI_MAX_NFUNCS;
  float  thrsh      = MPI_THRESHOLD;

  vector<times>    arr;

  ptr = getenv("IPM_OUTPUT_NFUNCS");
  if ( ptr ) {
    max_nfuncs = atoi(ptr);
    if ( max_nfuncs == 0) max_nfuncs = 1000000; // unlimited
  }

  ptr = getenv("IPM_OUTPUT_THRESHOLD");
  if ( ptr ) {
    thrsh = atof(ptr);
  }
  thrsh /= 100.;

  //header
  fprintf(f,
    "<table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "<tr>\n"
    "<th align=left bgcolor=lightblue colspan=10>\n"
    "Communication Event Statistics\n"
    "(%% detail, --- error) </th>\n"
    "</tr>\n"
    "<tr>\n"
    "<th align=left bgcolor=lightblue> &nbsp; </th>\n"
    "<th width=6%% align=left bgcolor=lightblue> Comm Size </th>\n"
    "<th align=left bgcolor=lightblue> Buffer Size </th>\n"
    "<th align=left bgcolor=lightblue> Ncalls </th>\n"
    "<th align=left bgcolor=lightblue> Total Time </th>\n"
    "<th align=left bgcolor=lightblue> Avg Time </th>\n"
    "<th align=left bgcolor=lightblue> Min Time </th>\n"
    "<th align=left bgcolor=lightblue> Max Time </th>\n"
    "<th align=left bgcolor=lightblue> %%MPI </th>\n"
    "<th align=left bgcolor=lightblue> %%Wall </th>\n"
    "</tr>\n"
  );

  create_sort_times(job, arr);

  wtime = data->app.wallt.dsum;
  mtime = data->app.mpi.dsum;

  for (std::vector<times>::iterator it=arr.begin(); it!=arr.end(); it++) {
    mproc = (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime;
    wproc = (wtime == 0.0) ? 100.0 : 100.0 * it->ttotal/wtime;
    fprintf(f,
      "<tr>\n"
      "<td align=left>%s</td>\n"
      "<td align=right> %d </td>\n"
      "<td align=right> %llu </td>\n"
      "<td align=right> %llu </td>\n"
      "<td align=right> %e </td>\n",
      job->funcnames[it->funcId].c_str(),
      it->comm_size,
      it->size,
      it->count,
      it->ttotal
    );
    avg = it->ttotal/it->count;
    size_t found = job->funcnames[it->funcId].find("_Wait");
    if (avg > thresh && found == string::npos) {
      fprintf(f, "<td align=right style='color:red'> %e </td>\n", avg);
    } else {
      fprintf(f, "<td align=right> %e </td>\n", avg);
    }
    fprintf(f,
      "<td align=right> %e </td>\n"
      "<td align=right> %e </td>\n"
      "<td align=right> %5.2f </td>\n"
      "<td align=right> %5.2f </td>\n"
      "</tr>\n",
      it->tmin,
      it->tmax,
      mproc,
      wproc
    );

    if (++count > max_nfuncs ) break;
    else if ( it->ttotal/mtime < thrsh ) break;
  }

  fprintf(f, "</table>\n");
}

void write_size_distrib_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& pl)
{
  double             time_max = 0.0;
  unsigned long long size_max = 0;
  unsigned long long call_max = 0;
  unsigned long long size_min = 16*1024*1024;
  FILE   *plot1 = NULL;
  FILE   *plot2 = NULL;

  const char *color = NULL;
  const char *fmt   = NULL;

  map<int, int> funcs;

  plot1 = pl.open_plot(job->result_dir(), "func_data");
  if ( plot1 == NULL ) {
    return;
  }

  // create new map <pair <ull, int>, funcdata >
  std::map< std::pair<unsigned long long, int>, funcdata_t > func_map;
  for (std::map<std::pair<comm_buffSize_t,int>, funcdata_t>::iterator it=job->func_list.begin();
              it!=job->func_list.end(); ++it) {
    if ( it->first.first.second == 0 ) continue;  // ignore transactions if message size is 0, but what about Barrier?
    std::pair<unsigned long long, int> size_funcId(it->first.first.second, it->first.second);
    func_map[size_funcId].time  += it->second.time;
    func_map[size_funcId].count += it->second.count;
  }

  for (std::map<std::pair<unsigned long long,int>, funcdata_t>::iterator it=func_map.begin();
              it!=func_map.end(); ++it) {
    fprintf(plot1,
      "%s %llu %llu %e\n",
      job->funcnames[it->first.second].c_str(), //it->first.second -> funcId
      it->first.first,  //size
      it->second.count, //count
      it->second.time   //ttotal for this size
    );
    size_max = MAX(size_max, it->first.first);
    size_min = MIN(size_min, it->first.first);
    call_max = MAX(call_max, it->second.count);
    time_max = MAX(time_max, it->second.time);
    funcs[it->first.second]=it->first.second;
  }
  fclose(plot1);

  plot1 = pl.open_plot(job->result_dir(), "mpi_buff_call_hist");
  plot2 = pl.open_plot(job->result_dir(), "mpi_buff_time_hist");
  if ( plot1 == NULL || plot2 == NULL ) {
    return;
  }

  if ( job->result_dir().empty() ) {
    fmt = "#proc getdata:\n    file: pl/func_data.txt\n\n";
  } else {
    fmt = "#proc getdata:\n    file: %s/pl/func_data.txt\n\n";
  }
  fprintf(plot1, fmt, job->result_dir().c_str());
  fprintf(plot2, fmt, job->result_dir().c_str());

  size_max = MAX(16*1024*1024, size_max);
  fmt = "#proc page\n  pagesize 10 8\n\n#proc areadef\nrectangle: 1 1 8 4\nxautorange: %llu %llu\nyautorange: 0 %llu\nyaxis.stubs: inc\nxscaletype: log\nyscaletype: log\nyaxis.label: %s\n\n";
  fprintf(plot1, fmt, size_min, size_max, call_max, "# calls");
  fmt = "#proc page\n  pagesize 10 8\n\n#proc areadef\nrectangle: 1 1 8 4\nxautorange: %llu %llu\nyautorange: 0 %e\nyaxis.stubs: inc\nxscaletype: log\nyscaletype: log\nyaxis.label: %s\n\n";
  fprintf(plot2, fmt, size_min, size_max, time_max, "time (s)");

#define FMT_ \
        ("#proc xaxis\n  label: Buffer size (bytes)\n  selflocatingstubs: text\n" \
        "\t1          1\n\t4          4\n\t16         16\n\t64         64\n\t256        256\n\t1024       1KB\n" \
        "\t4096       4KB\n\t16384      16KB\n\t65536      64KB\n\t262144     256KB\n\t1048576    1MB\n" \
        "\t4194304    4MB\n\t16777216   16MB\n\t67108864   64MB\n\t268435456  256MB\n\t1073741824 1GB\n\n")
  fprintf(plot1, FMT_);
  fprintf(plot2, FMT_);
#undef FMT_

  int i = 0;
  fmt = "#proc lineplot\nxfield: 2\nyfield: %d\nsort: yes\n"
        "select: @@1 = %s\nlinedetails: color=%s\nlegendlabel: %s\n"
        "pointsymbol: shape=circle linecolor=black radius=0.03 fillcolor=%s\n\n";
  for (map<int, int>::iterator it=funcs.begin(); it != funcs.end(); it++) {
    color = (i < sizeof(ipm_colors)/sizeof(char*)) ? ipm_colors[i] : "white";
    fprintf(plot1, fmt,
            3, job->funcnames[it->second].c_str(), color, job->funcnames[it->second].c_str(), color);
    fprintf(plot2, fmt, 
            4, job->funcnames[it->second].c_str(), color, job->funcnames[it->second].c_str(), color);
    i++;
  }

#define FMT_ ("#proc legend\n  location: max max\n\n")
  fprintf(plot1, FMT_);
  fprintf(plot2, FMT_);
#undef FMT_

  fclose(plot1);
  fclose(plot2);

  if ( pl.create_graph(job->result_dir(), "mpi_buff_call_hist") == -1 ||
       pl.create_graph(job->result_dir(), "mpi_buff_time_hist") == -1 ) {
    return;
  }

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <a name='bs'>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>Message Buffer Size Distributions: time</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/mpi_buff_time_hist.png\"></center></td></tr>\n"
    "  </table>\n"
    "</td>\n"
  );

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>Message Buffer Size Distributions: Ncalls</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/mpi_buff_call_hist.png\"></center></td></tr>\n"
    "  </table>\n"
    "</td>\n"
  );

}


void write_timings(FILE *f, job_t* job, banner_t *data, ploticus_t& pl)
{
  int i, j;
  int ntasks = job->ntasks + 1;
  region_t    *reg = &(job->ipm_main);
  taskdata_t  *td;

  FILE *plot = NULL;
  plot = pl.open_plot(job->result_dir(), "load_multi_data");
  if ( plot == NULL ) {
    return;
  }

#define PROC__(f1, f2) ( (f2 != .0) ? (100.*f1/f2) : (0.0) )
  for ( i = 0; i < job->ntasks; i++) {
    td = &job->taskdata[i];
           // rank, wtime utime stime mtime GF MEM
    fprintf(plot, "%d %f %f %f %f %f %f\n", i,
      PROC__(td->wtime, job->wtime_max),
      PROC__(td->utime, job->utime_max),
      PROC__(td->stime, job->stime_max),
      PROC__(td->mtime, job->mtime_max),
      PROC__(td->procmem, job->mem_max),
      PROC__(td->gflop, job->gflop_max)
    );
  }
  fprintf(plot, "\n");
  fclose(plot);
#undef PROC__

  const char *labels[]={"wtime", "utime", "stime", "mtime", "gbyte", "gflop"};
  string cmd;
  string filename;
  filename = job->result_dir() + "/pl/load_multi_data.txt";
  typedef struct ini{
    const char label[32];
    const char cmd[16];
    const char file[20];
  }ini_t;
  ini_t  arr[] = {
           "MPI Rank",                    " cat ",         "load_multi_rank",
           "Sorted by MPI time",          " sort -n -k5 ", "load_multi_mtime", // 5 here is mtime column in the table
           "Individually sorted indices", " sort -n -k",   "load_multi_all"
         };
  for ( i = 0; i < sizeof(arr)/sizeof(ini_t); i++) {
    plot = pl.open_plot(job->result_dir(), arr[i].file/*"load_multi_rank.txt"*/);
    if ( plot == NULL ) {
        return;
    }
    fprintf( plot,
        "#proc page\n  pagesize 10 8\n\n"
        "#proc areadef\n"
        "  rectangle: 1 1 7 4\n"
        "  xrange: 0 %d\n"
        "  yrange: 0 100\n"
        "  xaxis.stubs: inc\n"
        "  yaxis.stubs: inc\n"
        "  xaxis.stubrange: %d\n"
        "  xaxis.stubvert: yes\n"
        "  xaxis.label: %s\n"
        "  yaxis.label: %% of maximum across MPI ranks\n"
        "  xaxis.labeldistance: 0.5\n"
        "\n", ntasks, job->ntasks, arr[i].label
    );
    fprintf(plot, "\n");

    char key[16];
    for ( j = 0; j< (sizeof(labels)/sizeof(char*) ); j++) {
      cmd = arr[i].cmd;
      if ( i == 2 ) {
        snprintf(key, 15, "%d ", j+2); // field to sort on
        cmd += key;
      }
      cmd += filename;
      fprintf(plot, "\n#proc getdata:\n   command: %s\n", cmd.c_str());
      fprintf(plot, "\n#proc lineplot\n  yfield: %d\n  legendlabel: %s\n"
          "  linedetails: color=%s\n\n"
          "  sort: yes\n\n",
           j+2, labels[j], ipm_colors[j+1]
      );
    }
    fprintf(plot, "\n#proc legend\n  location: max+0.5 max\n  seglen: 0.3\n");
    fclose(plot);

    if ( pl.create_graph(job->result_dir(), arr[i].file) == -1 ) {
      return;
    }

  }

  const char *title1 = "Load balance by MPI time: memory, flops, timings";
  const char *title2 = "Load balance by MPI rank: memory, flops, timings";
  const char *title3 = "Load balance sorted by all indices: memory, flops, timings";
  const char *img1   = "load_multi_mtime.png";
  const char *img2   = "load_multi_rank.png";
  const char *img3   = "load_multi_all.png";

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <a name='lb'>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>%s</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/%s\"</center></td></tr>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>%s</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/%s\"</center></td></tr>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>%s</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/%s\"</center></td></tr>\n"
    "  </table>\n"
    "</td>\n",
    title1, img1, title2, img2, title3, img3
  );

}

void write_memusage_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& pl)
{
  int   i = 0;
  int   nhosts = job->nodes.size();

  FILE *plot = NULL;
  plot = pl.open_plot(job->result_dir(), "mem_stack_byhost");
  if ( plot == NULL ) {
    return;
  }

  fprintf(plot,
    "#proc page\n  pagesize 10 8\n\n#proc areadef\n  rectangle: 1 1 8 4\n  xrange: 0 %d\n  yrange:  0 %f\n  yaxis.stubs: inc\n"
    "  xaxis.stubvert: yes\n  yaxis.label: GBytes\n",
    nhosts+1, job->mem_max
  );
  fprintf(plot, "  xaxis.stubs: text\n");
  for ( map<string, double>::iterator it = job->mem_use.begin(); it != job->mem_use.end(); it++) {
    fprintf(plot, "        %s\n", it->first.c_str());  // host name
  }
  fprintf(plot, "\n#proc getdata\n  data:\n");
  for ( map<string, double>::iterator it = job->mem_use.begin(); it != job->mem_use.end(); it++) {
    fprintf(plot, "%d %f\n", i++, it->second); // nodeId, Mem Usage
  }
  fprintf(plot,
    "\n #proc bars\n  lenfield: 2\n  color: %s\n"
    "  barwidth: %f\n  outline: no\n  #saveas A\n\n",
    ipm_colors[1], 6.0/(nhosts+1)
  );
  fclose(plot);

  if ( pl.create_graph(job->result_dir(), "mem_stack_byhost") == -1 ) {
    return;
  }

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <a name='mu'>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>Memory Usage by host</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/mem_stack_byhost.png\"></center></td></tr>\n"
    "  </table>\n"
    "</td>\n"
  );
}

void write_mpi_ploticus_header(FILE *plot, job_t *job, double mtime, const char* str)
{
    fprintf(plot,
        "#proc page\n  pagesize 10 8\n\n"
        "#proc areadef\n"
        "  rectangle: 1 1 7 4\n"
        "  xrange: -1 %d\n"
        "  yrange:  0 %e\n"
        "  xaxis.stubs: inc\n"
        "  yaxis.stubs: inc\n"
        "  xaxis.stubrange: 0 %d\n"
        "  xaxis.stubvert: yes\n"
        "  xaxis.label: %s\n"
        "  xaxis.labeldistance: 0.5\n"
        "  yaxis.label: time in seconds\n"
        "\n"
        "#proc getdata\n",
        job->ntasks, mtime, job->ntasks, str
    );
}

void  write_mpi_stack_plot(FILE* plot, job_t* job, banner_t* data, vector<times>& arr, string& filename, const char* str)
{
  int i;
  int first_column;
  int locfield;
  write_mpi_ploticus_header(plot, job, data->app.mpi.dmax, str);
  fprintf(plot, "   file: %s\n\n", filename.c_str());
  if ( strcmp(str, "MPI rank") == 0 ) {
    locfield = 2;
  } else {
    locfield = 1;
  }
  first_column = 4;
  fprintf(plot,
             "#proc bars\n"
             "   lenfield: %d\n"
             "   locfield: %d\n"
             "   color: %s\n"
             "   legendlabel: %s\n"
             "   barwidth: %f\n"
             "   outline: no\n"
             "   #saveas A\n",
             first_column, locfield, ipm_colors[0], job->funcnames[arr[0].funcId].c_str(), 7.0/(float)(job->ntasks+1)
  );
  for (i = 1; i < arr.size(); i++) {
    fprintf(plot,
             "\n#proc bars\n"
             "   #clone: A\n"
             "   lenfield: %d\n"
             "   color: %s\n"
             "   legendlabel: %s\n"
             "   stackfields: *\n",
             first_column+i, i<32 ? ipm_colors[i] : "white", job->funcnames[arr[i].funcId].c_str()
    );
  }
  fprintf(plot, "\n#proc legend\n  location: max+0.5 max\n  seglen: 0.3\n");
}

class mtimes_ {
public:
    bool operator() (const std::pair<int, double> &left, const std::pair<int, double> &right) {
        // descending order
        return left.second > right.second;
    }
} mtimes_cmp;

// creates an image with MPI functions distribution per process
void write_mpi_perproc_graph(FILE *f, job_t* job, banner_t *data, ploticus_t& pl)
{
  int i, ntasks;
  int rank;
  double time, max;
  double wtime = 0.0;
  double mtime = 0.0;
  double pmpitime = 0.0; // mpi time for this process

  vector<times>    arr;

  FILE *plot1 = NULL;
  FILE *plot2 = NULL;
  plot1 = pl.open_plot(job->result_dir(), "task_data");
  if ( plot1 == NULL ) {
    return;
  }

  // get list of functions for the whole app
  times tm;
  for ( map<int, funcdata_t>::iterator it=job->funcs.begin(); it!=job->funcs.end(); ++it) {
      tm.funcId = it->first;
      tm.ttotal = it->second.time;
      arr.push_back(tm);
  }
  // sort the array based on TTotal (ttotal is for all processes) - descending 
  sort(arr.begin(), arr.end(), time_compare);

  std::vector<std::pair<int, double> > mtimes;
  for ( i=0; i < job->ntasks; i++ ) {
    mtimes.push_back(std::make_pair(i, job->taskdata[i].mtime));
  }
  // sort array of times
  sort(mtimes.begin(), mtimes.end(), mtimes_cmp);

  for ( i=0; i < job->ntasks; i++ ) {
    // Per process
    rank = mtimes[i].first;
    fprintf(plot1, "%d %d %e", i, rank, mtimes[i].second);
    for ( vector<times>::iterator it=arr.begin(); it != arr.end(); ++it ) {
      // TODO: how to deal with reg id? I use 1 for now ("MPI")
      fprintf(plot1, " %e", job->taskdata[rank].funcdata[std::make_pair(1, it->funcId)].time);
    }
    fprintf(plot1, "\n");
  }
  fclose(plot1);

  plot1 = pl.open_plot(job->result_dir(), "mpi_stack_byrank");
  plot2 = pl.open_plot(job->result_dir(), "mpi_stack_bymtime");
  if ( plot1 == NULL || plot2 == NULL) {
    return;
  }

  string filename = job->result_dir()+"/pl/task_data.txt";
  write_mpi_stack_plot(plot1, job, data, arr, filename, "MPI rank");
  fclose(plot1);

  write_mpi_stack_plot(plot2, job, data, arr, filename, "index (sorted by MPI time)");
  fclose(plot2);

  if ( pl.create_graph(job->result_dir(), "mpi_stack_byrank") == -1 ) {
    return;
  }
  if ( pl.create_graph(job->result_dir(), "mpi_stack_bymtime") == -1 ) {
    return;
  }

  const char *title1 = "Communication balance by task (sorted by MPI time)";
  const char *title2 = "Communication balance by task (sorted by MPI rank)";
  const char *img1   = "mpi_stack_bymtime.png";
  const char *img2   = "mpi_stack_byrank.png";

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <a name='cb'>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>%s</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/%s\"></center></td></tr>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>%s</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/%s\"></center></td></tr>\n"
    "  </table>\n"
    "</td>\n",
    title1, img1, title2, img2
  );
}

void write_p2p_matrix( FILE *f, job_t* job, banner_t *b, ploticus_t& pl )
{
  int i, j;
  int ntasks = job->ntasks + 1;
  double gray=1.0;

  FILE *plot = NULL;
  plot = pl.open_plot(job->result_dir(), "mpi_data_topo_send");
  if ( plot == NULL ) {
    return;
  }

  fprintf( plot,
    "#proc page\n  pagesize 10 8\n\n"
    "#proc areadef\n"
    "rectangle: 1 1 6 6\n"
    "frame: width=0.5 color=0.3\n"
    "xrange: -1 %d\n"
    "yrange: -1 %d\n"
    "xaxis.stubs: inc\n"
    "yaxis.stubs: inc\n"
    "xaxis.stubrange: 0\n"
    "yaxis.stubrange: 0\n"
    "xaxis.stubvert: yes\n"
    "xaxis.label: MPI_Rank\n"
    "yaxis.label: MPI_Rank\n"
    "\n", ntasks, ntasks
  );
  fprintf(plot, "\n");

  for ( i = 0; i < ntasks; i++) {
    for (j = 0; j < ntasks; j++) {
      std::pair<int, int> loc(i, j);
      if (job->p2p_matrix.count(loc) == 0 ) {
        gray = 1.0;
      } else {
        gray = (double)1.0 - job->p2p_matrix[loc]/job->p2p_max;
      }
      fprintf(plot, "#proc rect\n rectangle: %f(s) %f(s) %f(s) %f(s)\n color: gray(%f)\n\n", i-0.5, j-0.5, i+0.5, j+0.5, gray);
    }
  }
  for ( i = 0; i< 6; i++) {
    fprintf(plot, "#proc legendentry:\nsampletype: symbol\n");
    fprintf(plot, "details: style=outline fillcolor=gray(%.2f) shape=square linecolor=black\n", (float)i*20./100.);
    fprintf(plot, " label: %.0f MB\n", job->p2p_max * (1.0 - (float)i*20./100.) / (1024*1024));
  }
  fprintf(plot, "\n#proc legend\n  location: max+0.5 max-0.5\n");
  fclose(plot);

  if ( pl.create_graph(job->result_dir(), "mpi_data_topo_send") == -1 ) {
    return;
  }

  fprintf(f,
    "<td width=50%% valign=top>\n"
    "  <a name='ct'>\n"
    "  <table border=1 borderwidth=1 width=100%% cellpadding=0 cellspacing=0>\n"
    "    <tr> <th bgcolor=\"lightblue\"> <H3>Communication Topology : point to point data flow (data sent)</H3> </th> </tr>\n"
    "    <tr><td><center><img src=\"img/mpi_data_topo_send.png\"></center></td></tr>\n"
    "  </table>\n"
    "</td>\n"
  );

}

void write_host_list(FILE *f, job_t* job, banner_t *data)
{
  fprintf(f,
    "<a name='hl'>\n"
    "<table border=1 width=100%% cellpadding=0 cellspacing=0>\n<tr>\n"
    "<th valign=top align=left bgcolor=lightblue> Hostlist </th>\n"
    "<th valign=top align=left bgcolor=lightblue> Ranks </th>\n</tr>\n"
  );

  list<int>::iterator it3;
  for( list<node_t*>::iterator it = job->nodes.begin(); it != job->nodes.end(); it++) {
    fprintf(f, "<tr><td> %s </td>", (*it)->name.c_str());
    fprintf(f, "<td>");
    int prev    = -1;
    int skipped = 0;
    // list of ranks for this host
    for (list<int>::iterator it2 = (*it)->tasks.begin(); it2 != (*it)->tasks.end(); it2++ ) {
      it3 = it2;
      if ( prev == -1 ) {
        fprintf(f, "%d", (*it2)); // the first element
      } else {
        if ( (++it3) == (*it)->tasks.end() ) {
          // the last element
          fprintf(f, "%c%d", (skipped > 1) ? '-' : ',', (*it2));
        } else {
          if ( (*it2) - prev == 1 ) {
            skipped++;
          } else {
            if ( skipped ) {
              fprintf(f, "%c%d", (skipped == 1) ? ',' : '-', prev);
              skipped =0;
            }
            fprintf(f, ",%d", (*it2));
          }
        }
      }
      prev = (*it2);
    }
    fprintf(f, "</td></tr>\n");
  }
  fprintf(f, "</table>\n");
}

void write_mpi_funcs(FILE *f, job_t* job, banner_t *data)
{
  char  *ptr   = NULL;
  char  *csv   = NULL;
  int    count = 1;
  int    max_nfuncs = MPI_MAX_NFUNCS;
  float  thrsh      = MPI_THRESHOLD;
  double mtime = 0.0;
  double wtime = 0.0;

  ptr = getenv("IPM_OUTPUT_NFUNCS");
  if ( ptr ) {
    max_nfuncs = atoi(ptr);
    if ( max_nfuncs == 0) max_nfuncs = 1000000; // unlimited
  }

  ptr = getenv("IPM_OUTPUT_THRESHOLD");
  if ( ptr ) {
    thrsh = atof(ptr);
  }
  thrsh /= 100.;

  std::vector<times> arr;
  times tm;
  for (std::map<int, funcdata_t>::iterator it=job->funcs.begin();
    it!=job->funcs.end(); ++it) {
      tm.size   = 0;
      tm.funcId = it->first;
      tm.ttotal = it->second.time;
      tm.count  = it->second.count;
      arr.push_back(tm);
  }

  // sort the array based on TTotal - descending
  std::sort(arr.begin(), arr.end(), time_compare);

  wtime = data->app.wallt.dsum;
  mtime = data->app.mpi.dsum;

  csv = getenv("IPM_CSV_OUTPUT");
  if (csv) {
    fprintf(f, "#Func;TTotal;%%MPI;%%APP\n");
  } else {
    fprintf(f, "  Func           |   Time(sec)  |  %%MPI |  %%APP\n");
  }
  for (std::vector<times>::iterator it=arr.begin(); it!=arr.end(); it++) {
    if (csv) {
        fprintf(f, "%s,%f,%f,%f\n",
                     job->funcnames[it->funcId].c_str(),
                     it->ttotal,
                     (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime,
                     (wtime == 0.0) ? 100.0 : 100.0 * it->ttotal/wtime
                    );
    } else {
        fprintf(f, " %-15s | %12.4f | %5.2f | %5.2f\n",
                 job->funcnames[it->funcId].c_str(),
                 it->ttotal,
                 (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime,
                 (wtime == 0.0) ? 100.0 : 100.0 * it->ttotal/wtime
                );
    }
    if (++count > max_nfuncs ) {
      break;
    } else {
      if ( it->ttotal/mtime < thrsh ) {
        break;
      }
    }
  }

  fprintf(f, "\n\n");
}


void write_mpi_funcs_size(FILE *f, job_t* job, banner_t *data)
{
  char   *ptr  = NULL;
  char   *csv  = NULL;
  double  time = 0.0;
  double wtime = 0.0;
  double mtime = 0.0;
  int    count = 1;
  int    max_nfuncs = MPI_MAX_NFUNCS;
  float  thrsh      = MPI_THRESHOLD;

  ptr = getenv("IPM_OUTPUT_NFUNCS");
  if ( ptr ) {
    max_nfuncs = atoi(ptr);
    if ( max_nfuncs == 0) max_nfuncs = 1000000; // unlimited
  }

  ptr = getenv("IPM_OUTPUT_THRESHOLD");
  if ( ptr ) {
    thrsh = atof(ptr);
  }
  thrsh /= 100.;

  std::vector<times> arr;
  times tm;
  for (std::map<std::pair<comm_buffSize_t,int>, funcdata_t>::iterator it=job->func_list.begin();
    it!=job->func_list.end(); ++it) {
      tm.comm_size   = it->first.first.first;
      tm.size   = it->first.first.second;
      tm.funcId = it->first.second;
      tm.ttotal = it->second.time;
      tm.count  = it->second.count;
      arr.push_back(tm);
  }

  // sort the array based on TTotal - descending
  std::sort(arr.begin(), arr.end(), time_compare);

  wtime = data->app.wallt.dsum;
  mtime = data->app.mpi.dsum;

  csv = getenv("IPM_CSV_OUTPUT");
  if (csv) {
    fprintf(f, "#Func;CommSize;Size;Calls;TTotal;PerCall;%%MPI;%%APP\n");
  } else {
    fprintf(f, "  Func           |  CommSize  |  Size      |    #Calls    |   Time(sec)  | PerCall |  %%MPI |  %%APP\n");
  }
  for (std::vector<times>::iterator it=arr.begin(); it!=arr.end(); it++) {
    if (csv) {
        fprintf(f, "%s,%d,%llu,%llu,%f,%f,%f,%f\n",
                     job->funcnames[it->funcId].c_str(), it->comm_size,it->size,
                     it->count, it->ttotal, it->ttotal/it->count,
                     (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime,
                     (wtime == 0.0) ? 100.0 : 100.0 * it->ttotal/wtime
                    );
    } else {
        fprintf(f, " %-15s | %10d | %10llu | %12llu | %12.4f | %7.5f | %5.2f | %5.2f\n",
                 job->funcnames[it->funcId].c_str(), it->comm_size, it->size,
                 it->count, it->ttotal, it->ttotal/it->count,
                 (mtime == 0.0) ? 100.0 : 100.0 * it->ttotal/mtime,
                 (wtime == 0.0) ? 100.0 : 100.0 * it->ttotal/wtime
                );
    }
    if (++count > max_nfuncs ) {
      break;
    } else {
      if ( it->ttotal/mtime < thrsh ) {
        break;
      }
    }
  }
}

// prints the list of MPI functions on per process basis
void write_mpi_funcs_pp(FILE *f, job_t* job, banner_t *data)
{
  double time, max;
  double wtime = 0.0;
  double mtime = 0.0;
  double pmpitime = 0.0; // mpi time for this process

  max = 0.0;
  wtime = data->app.wallt.dmax;
  for ( int i=0; i<job->ntasks; i++ ) {
    // Per process
      for (std::map<std::pair<int,int>, funcdata_t>::iterator it=job->taskdata[i].funcdata.begin();
           it!=job->taskdata[i].funcdata.end(); ++it) {
          if ( it->first.second == 0 ) {
            mtime = it->second.time;
            continue;
          }
          pmpitime = it->second.time;
          fprintf(f, "Proc:%5d Func:%-13s Calls:%10llu Total:%7.3f per_call:%.5f %%MPI:%5.2f %%App:%5.2f\n",
                  i, job->funcnames[it->first.second].c_str(),
                  it->second.count, pmpitime,
                  pmpitime/it->second.count,
                  (mtime == 0.0) ? 100.0 : 100.0*pmpitime/mtime,
                  (wtime == 0.0) ? 100.0 : 100.0*pmpitime/wtime
                  );
      }
  }
}
#endif
