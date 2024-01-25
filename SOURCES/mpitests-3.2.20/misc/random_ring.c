/* #include "hpcc.h" */
#include "mpi.h"

#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

/* global vars */
FILE   *stderr;
double wtick;

#define WTICK_FACTOR 10

/* Message Tags */
#define PING 100
#define PONG 101
#define NEXT_CLIENT 102
#define TO_RIGHT 200
#define TO_LEFT  201

#ifndef CHECK_LEVEL
#  define CHECK_LEVEL 1
#endif

#ifndef DEBUG_LEVEL
#  define DEBUG_LEVEL 2
#endif

typedef struct {
  int    msglen;
  double ring_lat;
  double ring_bwidth;
  double rand_lat;
  double rand_bwidth;
} BenchmarkResult;

/* -----------------------------------------------------------------------
 * Routine: ring_lat_bw_loop()
 *
 *
 * Task: Communicate to left and right partner in rand_pattern_count
 *       random rings and the naturally ordered ring. Reduce the maximum
 *       of all measurements over all processors to rank 0 and get the
 *       minimal measurement on it. Compute naturally ordered and avg
 *       randomly ordered latency and bandwidth.
 *
 * Input:
 *   msglen, measurements, loop_length, rand_pattern_count
 *
 * Output:
 *   result->msglen, result->ring_lat, result->rand_lat,
 *   result->ring_bwidth, result->rand_bwidth
 *
 * Execution Tasks:
 *
 * - loop loop_length * measurements times and do Irecv,Isend to left
 *   and right partner as well as Sendrecv and save the minimum of both
 *   latencies for all rings.
 * - Reduce all measurements*(rand_pattern_count+1) latencies to rank 0
 *   and get minimal measurement on it.
 * - Compute latencies and bandwidth. For random order the geometric average
 * of the latency is built.
 * ----------------------------------------------------------------------- */
static
void ring_lat_bw_loop(
  int msglen,
  int measurements,
  int loop_length_proposal,
  int rand_pattern_count,
  BenchmarkResult *result)
{
  int i_meas, i_pat, i_loop, i, j;
  double start_time, end_time, lat_sendrecv, lat_nonblocking;
  double *latencies; /* measurements * (rand_pattern_count+1) */
  double *max_latencies; /* reduced from all processors with MPI_MAX on rank 0 */
  double avg_latency; /* of random pattern rings */
  int *ranks; /* communication pattern, order of processors */
  int size, myrank, left_rank, right_rank;
  MPI_Request requests[4];
  MPI_Status statuses[4];
  unsigned char *sndbuf_left, *sndbuf_right, *rcvbuf_left, *rcvbuf_right;
  long seedval;
  double rcp = 1.0 / RAND_MAX;
  int loop_length;
  int meas_ok, meas_ok_recv;
#if (CHECK_LEVEL >= 1)
  register int base;
#endif

  /* get number of processors and own rank */
  MPI_Comm_size(MPI_COMM_WORLD, &size);
  MPI_Comm_rank(MPI_COMM_WORLD, &myrank);

  /* alloc memory and init with 0 */
  latencies     = (double *)malloc( measurements * (rand_pattern_count+1) * sizeof( *latencies ) );
  max_latencies = (double *)malloc( measurements * (rand_pattern_count+1) * sizeof( *max_latencies ) );
  ranks = (int *)malloc( size * sizeof( *ranks ) );
  sndbuf_left  = (unsigned char *)malloc( msglen );
  sndbuf_right = (unsigned char *)malloc( msglen );
  rcvbuf_left  = (unsigned char *)malloc( msglen );
  rcvbuf_right = (unsigned char *)malloc( msglen );

  /* init pseudo-random with time seed */
#if (DEBUG_LEVEL >= 3)
//  seedval=(long)(time((time_t *) 0));
	seedval=(long)(3);
  if (myrank==0) { fprintf( stderr, "seedval = %ld\n",seedval); fflush( stderr ); }
#endif

  /* benchmark */
  for ( i_meas = 0; i_meas < measurements; i_meas++ ) {
    srand(seedval);
    for ( i_pat = 0; i_pat < rand_pattern_count+1; i_pat++ ) {
      /* build pattern at rank 0 and broadcast to all */
      if ( myrank == 0 ) {
        if (i_pat>0) { /* random pattern */
          for (i=0; i<size; i++) ranks[i] = -1;
          for (i=0; i<size; i++) {
            j = (int)(rand() * rcp * size);
            while (ranks[j] != -1) j = (j+1) % size;
            ranks[j] = i;
          }
        }
        else { /* naturally ordered ring */
          for (i=0; i<size; i++) ranks[i] = i;
        }
#if (DEBUG_LEVEL >= 3)
        if ( i_meas == 0 ) {
          fprintf( stderr, "i_pat=%3d: ",i_pat);
          for (i=0; i<size; i++) fprintf( stderr, " %2d",ranks[i]);
          fprintf( stderr,  "\n" );  fflush( stderr );
        }
#endif
      }
      MPI_Bcast(ranks, size, MPI_INT, 0, MPI_COMM_WORLD);

      /* get rank of left and right partner. therefore find myself (myrank)
       * in pattern first. */
      for ( i = 0; i < size; i++ )
        if ( ranks[i] == myrank ) { /* will definitely be found */
          left_rank = ranks[(i-1+size)%size];
          right_rank = ranks[(i+1)%size];
		  //break;
        }
		
		if ( ranks[size/2] == myrank )
			right_rank = ranks[0];
		if ( ranks[0] == myrank )
			left_rank = ranks[size/2];
		if ( ranks[size - 1] == myrank )
			right_rank = ranks[(size/2 +1)%size];
		if ( ranks[(size/2 + 1)%size] == myrank )
			left_rank = ranks[size -1];
		
		
		
      do
      {
        meas_ok = 0;
        MPI_Allreduce (&loop_length_proposal, &loop_length, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
        loop_length_proposal = loop_length;

        /* loop communication */
        for ( i_loop = -1; i_loop < loop_length; i_loop++ ) {
          if ( i_loop == 0 ) start_time = MPI_Wtime();

          /* communicate to left and right partner */
#if (CHECK_LEVEL >= 1)
          base = (i_loop + myrank + 1)&0x7f; /* = mod 128 */
          sndbuf_right[0] = base; sndbuf_right[msglen-1] = base+1;
          sndbuf_left[0]  = base+2; sndbuf_left[msglen-1]  = base+3;
# if (CHECK_LEVEL >= 2)
          /* check the check: use a wrong value on process 1 */
          if (myrank == 1) sndbuf_right[0] = sndbuf_right[0] + 33;
          if (myrank == 1) sndbuf_left[msglen-1] = sndbuf_left[msglen-1] + 44;
# endif
#endif
          MPI_Sendrecv(
            sndbuf_right, msglen, MPI_BYTE,
            right_rank, TO_RIGHT,
            rcvbuf_left, msglen, MPI_BYTE,
            left_rank, TO_RIGHT,
            MPI_COMM_WORLD, &(statuses[0]) );
          MPI_Sendrecv(
            sndbuf_left, msglen, MPI_BYTE,
            left_rank, TO_LEFT,
            rcvbuf_right, msglen, MPI_BYTE,
            right_rank, TO_LEFT,
            MPI_COMM_WORLD, &(statuses[1]) );
#if (CHECK_LEVEL >= 1)
          /* check whether bytes are received correctly */
          base = (i_loop + left_rank + 1)&0x7f; /* = mod 128 */
          if ( rcvbuf_left[0] != base || rcvbuf_left[msglen-1] != base+1 )
          {
            fprintf( stderr,  "[%d]: ERROR: from right: expected %u and %u as first and last byte, but got %u and %u instead\n",
            myrank, base, base+1,
            rcvbuf_left[0], rcvbuf_left[msglen-1] ); fflush( stderr );
          }
          base = (i_loop + right_rank + 1)&0x7f; /* = mod 128 */
          if ( rcvbuf_right[0] != base+2 || rcvbuf_right[msglen-1] != base + 3 )
          {
            fprintf( stderr,  "[%d]: ERROR: from right: expected %u and %u as first and last byte, but got %u and %u instead\n",
            myrank, base+2, base+3,
            rcvbuf_right[0], rcvbuf_right[msglen-1] ); fflush( stderr );
          }
#endif
        }
        end_time = MPI_Wtime();
        if ((end_time-start_time) < WTICK_FACTOR * wtick)
        {
          if (loop_length_proposal == 1) loop_length_proposal = 2;
          else loop_length_proposal = loop_length_proposal * 1.5;
        }
        else meas_ok=1;
        MPI_Allreduce (&meas_ok, &meas_ok_recv, 1, MPI_INT, MPI_MAX, MPI_COMM_WORLD);
        meas_ok = meas_ok_recv;
      }
      while (!meas_ok);
      lat_sendrecv = (end_time-start_time) / (2 * loop_length);

      /* communication loop with non-blocking routines, and previous loop_length */
      for ( i_loop = -1; i_loop < loop_length; i_loop++ ) {
        if ( i_loop == 0 ) start_time = MPI_Wtime();
#if (CHECK_LEVEL >= 1)
        /* communicate to left and right partner */
        base = (i_loop + myrank + 1)&0x7f; /* = mod 128 */
        sndbuf_right[0] = base; sndbuf_right[msglen-1] = base+1;
        sndbuf_left[0]  = base+2; sndbuf_left[msglen-1]  = base+3;
#endif
        /* irecv left */
        MPI_Irecv(
          rcvbuf_left, msglen, MPI_BYTE,
          left_rank, TO_RIGHT,
          MPI_COMM_WORLD, &requests[0] );
        /* irecv right */
        MPI_Irecv(
          rcvbuf_right, msglen, MPI_BYTE,
          right_rank, TO_LEFT,
          MPI_COMM_WORLD, &requests[1] );
        /* isend right */
        MPI_Isend(
          sndbuf_right, msglen, MPI_BYTE,
          right_rank, TO_RIGHT,
          MPI_COMM_WORLD, &requests[2] );
        /* isend left */
        MPI_Isend(
          sndbuf_left, msglen, MPI_BYTE,
          left_rank, TO_LEFT,
          MPI_COMM_WORLD, &requests[3] );
        /* waitall */
        MPI_Waitall( 4, requests, statuses );
#if (CHECK_LEVEL >= 1)
        /* check whether both transfers were done right */
        base = (i_loop + left_rank + 1)&0x7f; /* = mod 128 */
        if ( rcvbuf_left[0] != base || rcvbuf_left[msglen-1] != base+1 )
        {
          fprintf( stderr,  "[%d]: ERROR: from right: expected %u and %u as first and last byte, but got %u and %u instead\n",
          myrank, base, base+1,
          rcvbuf_left[0], rcvbuf_left[msglen-1] ); fflush( stderr );
        }
        base = (i_loop + right_rank + 1)&0x7f; /* = mod 128 */
        if ( rcvbuf_right[0] != base+2 || rcvbuf_right[msglen-1] != base + 3 )
        {
          fprintf( stderr,  "[%d]: ERROR: from right: expected %u and %u as first and last byte, but got %u and %u instead\n",
          myrank, base+2, base+3,
          rcvbuf_right[0], rcvbuf_right[msglen-1] ); fflush( stderr );
        }
#endif
      }
      end_time = MPI_Wtime();
      lat_nonblocking = (end_time-start_time) / ( 2 * loop_length );

      /* workaround to fix problems with MPI_Wtime granularity */
      if (!lat_nonblocking)
      {
        static int complain = 0;
        lat_nonblocking = wtick;
        if (complain != loop_length)
        {
#define MSG "In " __FILE__ ", routine bench_lat_bw, the 3rd parameter to ring_lat_bw_loop was %d; increase it.\n"
          fprintf( stderr, MSG, loop_length);
          fprintf( stderr, MSG, loop_length);
#undef MSG
        }
        complain = loop_length;
      }

      latencies[i_meas*(rand_pattern_count+1)+i_pat] =
      (lat_sendrecv < lat_nonblocking ? lat_sendrecv : lat_nonblocking);
    }
  }

#if (DEBUG_LEVEL >= 5)
  if ((myrank == 0) || (DEBUG_LEVEL >= 6)) {
    fprintf( stderr,  "RANK %3d: ", myrank );
    for ( i = 0; i < measurements*(rand_pattern_count+1); i++ )
      fprintf( stderr,  "%e  ", latencies[i] );
    fprintf( stderr,  "\n" ); fflush( stderr );
  }
#endif

  /* reduce all vectors to get maximum vector at rank 0 */
  MPI_Reduce(
    latencies, max_latencies,
    measurements * (rand_pattern_count+1), MPI_DOUBLE,
    MPI_MAX, 0, MPI_COMM_WORLD );

#if (DEBUG_LEVEL >= 5)
       fflush(stdout);
       MPI_Barrier(MPI_COMM_WORLD);
       if (myrank==0)
       {
         fprintf( stderr,  "RANK ---: " );
         for ( i = 0; i < measurements*(rand_pattern_count+1); i++ )
           fprintf( stderr,  "%e  ", max_latencies[i] );
         fprintf( stderr,  "\n" ); fflush( stderr );
       }
#endif

  /* get minimal measurement from vector as final measurement and compute latency and bandwidth */
  if ( myrank == 0 ) {
    /* reduce measurements to first minimal measurement */
    for ( i_pat = 0; i_pat < rand_pattern_count+1; i_pat++ )
    {
      for (i_meas = 1; i_meas < measurements; i_meas++)
      { /* minimal latencies over all measurements */
        if (max_latencies[i_meas*(rand_pattern_count+1)+i_pat] < max_latencies[i_pat])
          max_latencies[i_pat] = max_latencies[i_meas*(rand_pattern_count+1)+i_pat];
      }
    }

    /* get average latency of random rings by geometric means */
    avg_latency = 0;
    for ( i_pat = 1; i_pat < rand_pattern_count+1; i_pat++ )
    avg_latency += log( max_latencies[i_pat] );
    avg_latency = avg_latency / rand_pattern_count;
    avg_latency = exp( avg_latency );

    /* compute final benchmark results */
    result->msglen = msglen;
    result->ring_lat = max_latencies[0];
    result->ring_bwidth = msglen / max_latencies[0];
    result->rand_lat = avg_latency;
    result->rand_bwidth = msglen / avg_latency;
  }

  /* free memory */
  free( ranks );
  free( latencies );
  free( max_latencies );
  free(sndbuf_left);
  free(sndbuf_right);
  free(rcvbuf_left);
  free(rcvbuf_right);
#if (DEBUG_LEVEL >= 2)
   if (myrank == 0)
   {
     fprintf( stderr,  "Message Size:               %13d Byte\n",   result->msglen );
     fprintf( stderr,  "Natural Order Latency:      %13.6f msec\n", result->ring_lat*1e3 );
     fprintf( stderr,  "Natural Order Bandwidth:    %13.6f MB/s\n", result->ring_bwidth/1e6 );
     fprintf( stderr,  "Avg Random Order Latency:   %13.6f msec\n", result->rand_lat*1e3 );
     fprintf( stderr,  "Avg Random Order Bandwidth: %13.6f MB/s\n", result->rand_bwidth/1e6 );
     fprintf( stderr,  "\n" );
     fflush( stderr );
   }
#endif
}


int main(int argc, char *argv[])
{
	int rc, myrank;
	int msg_length_for_lat = 8;
	int msg_length_for_bw  = 2000000;

	BenchmarkResult result_lat, result_bw;

	double ring_lat; /* naturally ordered ring latency */
	double rand_lat; /* randomly  ordered ring latency */
	double ring_bw;  /* randomly  ordered ring bandwidth */
	double rand_bw;  /* naturally ordered ring bandwidth */

	double RandomlyOrderedRingLatency;
	double wtick_recv;

	rc = MPI_Init(&argc, &argv);
	if( MPI_SUCCESS != rc )
	{
		fprintf (stderr, "\nError starting MPI program. Terminating.\n");
		fflush(stderr);

		MPI_Abort(MPI_COMM_WORLD, rc);
        return 0;
	}

    MPI_Comm_rank( MPI_COMM_WORLD, &myrank );

	/* get the granularity of MPI_Wtime, but don't trust MPI_Wtick!! */
	wtick = MPI_Wtick();
# ifdef SET_WTICK
	wtick = SET_WTICK ;
# endif
	if (wtick < 0) wtick = -wtick;
	MPI_Allreduce (&wtick, &wtick_recv, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
	wtick = wtick_recv;
# if (DEBUG_LEVEL >= 1)
	if (myrank == 0)
	{
		fprintf(stderr, "MPI_Wtime granularity.\n");
		fprintf(stderr, "Max. MPI_Wtick is %f sec\n", wtick);
	}
# endif
	if (wtick < 1e-6) wtick = 1e-6;
	if (wtick > 0.01) wtick = 0.01;
# if (DEBUG_LEVEL >= 1)
	if (myrank == 0)
	{
		fprintf(stderr, "wtick is set to   %f sec  \n\n", wtick);
		fflush(stderr );
	}
# endif



	ring_lat_bw_loop( msg_length_for_lat, 8, 5, 30, &result_lat );
	ring_lat = result_lat.ring_lat;
	rand_lat = result_lat.rand_lat;

	ring_lat_bw_loop( msg_length_for_bw,  3, 2, 10, &result_bw );
	ring_bw = result_bw.ring_bwidth;
	rand_bw = result_bw.rand_bwidth;

    RandomlyOrderedRingLatency = rand_lat * 1e6; /* usec */


	if (myrank == 0 )
	{
		fprintf( stderr,  "On naturally ordered ring: latency= %13.6f msec, bandwidth= %13.6f MB/s\n", ring_lat*1e3, ring_bw/1e6);
		fprintf( stderr,  "On randomly  ordered ring: latency= %13.6f msec, bandwidth= %13.6f MB/s\n", rand_lat*1e3, rand_bw/1e6);
		
		fflush(stderr);
	}

    MPI_Finalize();

	return 0;
}









