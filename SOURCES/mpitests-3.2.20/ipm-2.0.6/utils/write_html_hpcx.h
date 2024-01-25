#ifndef WRITE_HTML_HPCX_H_INCLUDED
#define WRITE_HTML_HPCX_H_INCLUDED

#include <sstream>
#include <sys/stat.h>
#include <stdlib.h>
#include <string>

using std::string;
void write_html_hpcx(job_t *job, banner_t *b);
void write_mpi_funcs_size(FILE *f, job_t *job, banner_t *);


#define MPI_MAX_NFUNCS   60
#define MPI_THRESHOLD    (0.05) // 0.05%
#define PLOTICUS_BIN     "/hpc/local/bin/pl"
#define PLOTICUS_FLAGS   " -maxproclines 1000000 -maxfields 10000000 -maxvector 1000000 -maxrows 1000000 -cpulimit 500 "
typedef struct ploticus
{
  string        pl_path;

  ploticus()
  {
    const char   *str;
    struct stat buf;
    if ( (str = getenv("IPM_PLOTICUS_BIN")) != NULL && *str != '\0') {
    } else {
      str = PLOTICUS_BIN;
    }
    if ( stat(str, &buf) ) {
      fprintf(stderr, "There is no Ploticus binary: %s. Set IPM_PLOTICUS_BIN environment variable with full path to \'pl\' binary.\n", str);
      pl_path.clear();
    } else {
      pl_path = string(str);
    }
  }

  FILE* open_plot(const string& result_dir, const char* file)
  {
    FILE   *F = NULL;
    string  path;
    struct stat buf;
    const char *dir = "pl/";

    if ( dir && dir[0] != 0 ) {
      path = result_dir + "/";
      path += dir;
      path += '/';

      // check existance of the dir
      if ( stat(path.c_str(), &buf) ) {
        if ( mkdir(path.c_str(), S_IRWXU | S_IRWXG)  ) {
          fprintf(stderr, "Could not create directory: %s\n", path.c_str());
          return NULL;
        }
      }
      if ( file ) {
        path += file;
        path += ".txt";
        F = fopen(path.c_str(), "w");
        if ( F == NULL ) {
          fprintf(stderr, "Could not create file: %s\n", path.c_str());
        }
      }
    }
    return F;
  }

  int create_graph(const string &result_dir, const char* name)
  {
    struct stat buf;
    string cmd;

    if ( pl_path.empty() ) {
      return -1;
    }

    cmd = result_dir + "/img/";
    if ( stat(cmd.c_str(), &buf) ) {
      if ( mkdir(cmd.c_str(), S_IRWXU | S_IRWXG)  ) {
        fprintf(stderr, "Could not create directory: %s\n", cmd.c_str());
        return -1;
      }
    }
    cmd.clear();

    cmd  = pl_path;
    cmd += PLOTICUS_FLAGS;
    cmd += result_dir + "/pl/" + string(name) + ".txt -png -o " + result_dir + "/img/" + string(name) +".png";
    if ( system(cmd.c_str()) != 0 ) {
      fprintf(stderr, "Could not execute ploticus command: %s\n", cmd.c_str());
      return -1;
    }

    return 0;
  }
} ploticus_t;

#endif /* WRITE_HTML_HPCX_H_INCLUDED */
