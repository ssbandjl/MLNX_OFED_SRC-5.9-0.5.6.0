#ifndef MOD_COMMSIZE_H
#define MOD_COMMSIZE_H
#include "hashkey.h"
#include "mpi.h"
#include "ipm_modules.h"

/* ---- initialize the module ---- */
int mod_commsize_init(ipm_mod_t* mod, int flags);

/* Get communicator ID if it exists or register new one */
int get_commsize_id(MPI_Comm comm);

#endif /* MOD_COMMSIZE_H */
