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

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>


#if __FreeBSD_version < 500000
#define VM_OBJECT_LOCK(x) do { } while (0)
#define VM_OBJECT_UNLOCK(x) do { } while (0)
#define PROCP(td) (td)
#define RETVAL p_retval
#define thread proc
#else
#define PROCP(td) (td)->td_proc
#define RETVAL td_retval
#endif

struct getpath_fromaddr_args {
	void *addr;
	char *buf;
	int len;
};

static int getpath_fromaddr_num = NO_SYSCALL;
SYSCTL_INT(_machdep, OID_AUTO, getpath_fromaddr_num, CTLFLAG_RD, &getpath_fromaddr_num, 0,
    "syscall number for __getpath_fromaddr()");

static int
getpath_fromaddr_syscall(struct thread *td, void *args)
{
	struct getpath_fromaddr_args *uap = (struct getpath_fromaddr_args *)args;
	int len;
	int error;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t obj, bobj;
	struct vnode *vp;
	char *path, *freebuf;

	map = &PROCP(td)->p_vmspace->vm_map;

	error = 0;
	/* vm_map_lock_read(map); procfs says not needed for curthread's map */
	for (entry = map->header.next; entry != &map->header; entry = entry->next) {
		if (entry->eflags & MAP_ENTRY_IS_SUB_MAP)
			continue;
		if ((vm_offset_t)uap->addr < entry->start ||
		    (vm_offset_t)uap->addr >= entry->end)
			continue;
		obj = entry->object.vm_object;
		VM_OBJECT_LOCK(obj);
		while (obj->backing_object) {
			bobj = obj->backing_object;
			VM_OBJECT_LOCK(bobj);
			VM_OBJECT_UNLOCK(obj);
			obj = bobj;
		}
		if (obj == NULL || obj->type != OBJT_VNODE)
			continue;
		vp = (struct vnode *)obj->handle;
		if (vp == NULL)
			continue;		/* XXX should panic */
		/* vref(vp); procfs says no, imgact_elf says maybe */
		error = vn_fullpath(td, vp, &path, &freebuf);
		/* vrele(vp); procfs says no, imgact_elf says maybe */
		if (error == 0) {
			len = strlen(path);
			if ((len + 1) > uap->len)
				error = ENOMEM;
			else
				error = copyout(path, uap->buf, len + 1);
			free(freebuf, M_TEMP);
			td->RETVAL[0] = len;
			break;
		}
	}
	/* vm_map_unlock_read(map); */
	return (error);
}

static struct sysent getpath_fromaddr_sysent = {
	sizeof(struct getpath_fromaddr_args) / sizeof(register_t),
	getpath_fromaddr_syscall,
};
	
static int
getpath_fromaddr_dispatch(struct module *module, int cmd, void *arg)
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

SYSCALL_MODULE(getpath_fromaddr, &getpath_fromaddr_num, &getpath_fromaddr_sysent, getpath_fromaddr_dispatch, NULL);

