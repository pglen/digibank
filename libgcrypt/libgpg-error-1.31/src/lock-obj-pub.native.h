## lock-obj-pub.i686-pc-msys.h
## File created by gen-posix-lock-obj - DO NOT EDIT
## To be included by mkheader into gpg-error.h

typedef struct
{
  long _vers;
  union {
    volatile char _priv[4];
    long _x_align;
    long *_xp_align;
  } u;
} gpgrt_lock_t;

#define GPGRT_LOCK_INITIALIZER {1,{{19,0,0,0}}}
##
## Local Variables:
## mode: c
## buffer-read-only: t
## End:
##
