#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/types.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/resourcevar.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/sysent.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>

#if __FreeBSD_version < 500000
#define PROCP(td) (td)
#define RETVAL p_retval
#define thread proc
#define FDROP(td, fd) do { } while (0)
#define VNODE(fp) (struct vnode *)(fp)->f_data
#else
#define PROCP(td) (td)->td_proc
#define RETVAL td_retval
#define FDROP(td, fd) fdrop(td, fd)
#define VNODE(fp) (fp)->f_vnode
#endif
struct getpath_fromfd_args {
	int fd;
	char *buf;
	int len;
};

static int getpath_fromfd_num = NO_SYSCALL;
SYSCTL_INT(_machdep, OID_AUTO, getpath_fromfd_num, CTLFLAG_RD, &getpath_fromfd_num, 0,
    "syscall number for __getpath_fromfd()");

static int
getpath_fromfd_syscall(struct thread *td, void *args)
{
	struct getpath_fromfd_args *uap = (struct getpath_fromfd_args *)args;
	struct filedesc *fdp = PROCP(td)->p_fd;
	struct file *fp;
	struct vnode *vp;
	int len, error;
	char *path, *freebuf = NULL;

	/* getvnode does internal filedesc locking (on 6.x) and returns a reference to fp */
	error = getvnode(fdp, uap->fd, &fp);
	if (error)
		return (error);
	if (fp->f_type != DTYPE_VNODE) {
		FDROP(fp, td);	/* 6.x getvnode returns with an fd hold */
		return (EOPNOTSUPP);
	}
	/* On 4,x depend on not sleeping before this point */
	vp = VNODE(fp);
	vref(vp);		/* as per kern_proc.c use of vn_fullpath */
	error = vn_fullpath(td, vp, &path, &freebuf);
	vrele(vp);
	FDROP(fp, td);
	if (error == 0) {
		len = strlen(path);
		if ((len + 1) > uap->len)
			error = ENOMEM;
		else
			error = copyout(path, uap->buf, len + 1);
		free(freebuf, M_TEMP);
		td->RETVAL[0] = len;
	}
	return (error);
}

static struct sysent getpath_fromfd_sysent = {
	sizeof(struct getpath_fromfd_args) / sizeof(register_t),
	getpath_fromfd_syscall,
};
	
static int
getpath_fromfd_dispatch(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
	case MOD_UNLOAD:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

SYSCALL_MODULE(getpath_fromfd, &getpath_fromfd_num, &getpath_fromfd_sysent, getpath_fromfd_dispatch, NULL);

