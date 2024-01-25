#include "mod_commsize.h"
#include "perfdata.h"
#include <stdlib.h>

static int printed=0;

int mod_commsize_init(ipm_mod_t *mod, int flags)
{
  int i;

  mod->state    = STATE_IN_INIT;
  mod->init     = mod_commsize_init;
  mod->output   = 0;
  mod->finalize = 0;
  mod->name     = "COMMSIZE";

  task.ncomm = 1;
  task.comms = (int *)IPM_MALLOC(task.ncomm*sizeof(int));
  if (task.comms == NULL) {
    fprintf(stderr, "Out of memory\n");
    exit(-1);
  }
  task.comms[0] = 0; // the first element always has size 0 and it always exists

  mod->state    = STATE_ACTIVE;
  return IPM_OK;
}

#define COMMS_BASKET_SIZE 64*1024

/* range should be 64K - int is enough */
/* there is no Id 0 */
int get_commsize_id(MPI_Comm comm)
{
  int size, idx, comms_in_basket;

  if ( comm == MPI_COMM_NULL ) {
    size = 0;
  } else {
    PMPI_Comm_size(comm, &size);
  }

  for ( idx = 0; idx < task.ncomm && idx < KEY_MAX_COMMSIZE; idx++ ) {
    if ( task.comms[idx] == size ) {
      return idx;
    }
  }

  if ( idx == KEY_MAX_COMMSIZE ) {
    // The last available index was used
    if (!printed ) {
      fprintf(stderr, "Too many different communicators\n");
      printed = 1;
    }
    return 0;
  }

  comms_in_basket = COMMS_BASKET_SIZE / sizeof(int);
  if (idx % comms_in_basket == 0) {
//  printf("Allocate new array with size %d\n", COMMS_BASKET_SIZE * (idx / comms_in_basket) + 1) );
    task.comms=(int *)IPM_REALLOC(task.comms, COMMS_BASKET_SIZE * (idx / (comms_in_basket) + 1) );
    if (task.comms == NULL) {
      fprintf(stderr, "Out of memory\n");
      exit(-1);
    }
  }
  task.ncomm = idx + 1;
  task.comms[idx] = size;

  return idx;
}
