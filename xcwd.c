#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#define DEBUG                           0
#define NAMELEN                         16

#define LOG(fmt, ...)                   do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define STR_HELPER(X)                   #X
#define STR(X)                          STR_HELPER(X)

#define DEVPTS                          "/dev/pts"

#define XA_CARDINAL                     (XInternAtom(dpy, "CARDINAL", False))
#define XA_STRING                       (XInternAtom(dpy, "STRING", False))
#define XA_WM_CLASS                     (XInternAtom(dpy, "WM_CLASS", False))
#define XA_NET_WM_PID                   (XInternAtom(dpy, "_NET_WM_PID", False))

typedef struct {
        long pid;
        char name[NAMELEN];
        long ppid;
} Process;

typedef struct {
        Process *ps;
        size_t n;
} Processes;

static int deepestchildcwd(Processes *p, long pid);
static Window focusedwin();
static void freeprocesses(Processes *p);
static Processes *getprocesses(int onlytty);
static int istty(long pid);
static int namecmp(const void *p1, const void *p2);
static int ppidcmp(const void *p1, const void *p2);
static int printcwd(Process *ps);
static long winpid(Window win);

Display *dpy;

int
deepestchildcwd(Processes *p, long pid)
{
        int i;
        Process key = { .pid = pid, .ppid = pid };
        Process *res = NULL, *fres = NULL;

        do {
                if (res) {
                        fres = res;
                        key.ppid = res->pid;
                }
                res = (Process *)bsearch(&key, p->ps, p->n, sizeof(Process), ppidcmp);
        } while (res);

        if (!fres)
                return printcwd(&key);
        for (i = 0; fres != p->ps && (fres - i)->ppid == fres->ppid; i++)
                if (printcwd(fres - i))
                        return 1;
        for (i = 1; fres != p->ps + p->n && (fres + i)->ppid == fres->ppid; i++)
                if (printcwd(fres + i))
                        return 1;
        return 0;
}

Window
focusedwin()
{
        int di;
        unsigned int du;
        Window win, winr, winp;
        Window *winc;

        if (!(dpy = XOpenDisplay(NULL))) {
                fputs("Error: could not open display.\n", stderr);
                exit(2);
        }
        XGetInputFocus(dpy, &win, &di);
        if (win == DefaultRootWindow(dpy))
                return None;
        while (XQueryTree(dpy, win, &winr, &winp, &winc, &du) && winp != winr)
                win = winp;
        if (winc)
                XFree(winc);
        LOG("focusedwin: window id = %lu\n", win);
        return win;
}

void
freeprocesses(Processes *p)
{
        free(p->ps);
        free(p);
}

Processes *
getprocesses(int onlytty)
{
        unsigned int i, j;
        glob_t globbuf;
        Processes *p = NULL;

        glob("/proc/[0-9]*", GLOB_NOSORT, NULL, &globbuf);
        p = malloc(sizeof(Processes));
        p->ps = malloc(globbuf.gl_pathc * sizeof(Process));

        for (i = j = 0; i < globbuf.gl_pathc; i++) {
                char d;
                char path[32], line[64];
                char *fb, *lb;
                char *proc = globbuf.gl_pathv[globbuf.gl_pathc - i - 1];
                FILE *fp;

                /* skip kernel processes */
                snprintf(path, sizeof path, "%s%s", proc, "/exe");
                if (readlink(path, &d, 1) == -1)
                        continue;

                snprintf(path, sizeof path, "%s%s", proc, "/stat");
                if (!(fp = fopen(path, "r")))
                        continue;
                if (!fgets(line, sizeof line, fp)) {
                        fclose(fp);
                        continue;
                }
                fclose(fp);
                p->ps[j].pid = atol(line);
                if (onlytty && !istty(p->ps[j].pid)) {
                        LOG("getprocesses: skipping %ld, not a tty process\n",
                                        p->ps[j].pid);
                        continue;
                }
                fb = strchr(line, '(');
                lb = strrchr(line, ')');
                *lb = '\0';
                strcpy(p->ps[j].name, fb + 1);
                p->ps[j].ppid = atol(lb + 4);
                LOG("getprocesses: %" STR(NAMELEN) "s, pid = %6ld, ppid = %6ld\n",
                                p->ps[j].name, p->ps[j].pid, p->ps[j].ppid);
                j++;
        }
        p->n = j;
        globfree(&globbuf);
        return p;
}

int
istty(long pid)
{
        char fd0[sizeof DEVPTS - 1];
        char path[32];
        ssize_t rd;

        snprintf(path, sizeof path , "/proc/%ld/fd/0", pid);

        if ((rd = readlink(path, fd0, sizeof fd0)) == -1) {
                LOG("istty: readlink %s failed\n", path);
                return 0;
        }
        return !strncmp(fd0, DEVPTS, sizeof fd0);
}

int
namecmp(const void *p1, const void *p2)
{
        return strcasecmp(((Process *)p1)->name, ((Process *)p2)->name);
}

int
ppidcmp(const void *p1, const void *p2)
{
        return ((Process *)p1)->ppid - ((Process *)p2)->ppid;
}

int
printcwd(Process *ps)
{
        char path[32];
        char *cwd;
        ssize_t rd, sz = 256;
        struct stat buf;

        snprintf(path, sizeof path , "/proc/%ld/cwd", ps->pid);

        for(cwd = NULL; ; sz *= 2) {
                cwd = realloc(cwd, sz);
                rd = readlink(path, cwd, sz);
                if (rd == -1) {
                        LOG("printcwd: readlink %s failed\n", path);
                        free(cwd);
                        return 0;
                } else if (rd < sz)
                        break;
                sz *= 2;
        }
        cwd[rd] = '\0';
        if (stat(cwd, &buf) == -1 || !S_ISDIR(buf.st_mode)) {
                LOG("printcwd: %s is not a directory\n", cwd);
                free(cwd);
                return 0;
        }
        fprintf(stdout, "%s\n", cwd);
        free(cwd);
        return 1;
}

long
winpid(Window win)
{
        int di;
        unsigned long dl;
        unsigned char *p;
        Atom da;
        long pid = -1;

        if (XGetWindowProperty(dpy, win, XA_NET_WM_PID, 0L, 1L, False, XA_CARDINAL,
                               &da, &di, &dl, &dl, &p) == Success && p) {
                pid = *(long *)p;
                XFree(p);
                LOG("winpid: _NET_WM_PID = %ld\n", pid);
        } else
                LOG("%s", "winpid: _NET_WM_PID not found\n");
        return pid;
}

int
main(int argc, char *argv[])
{
        int onlytty = 0;
        Window win;
        long pid;
        Processes *p = NULL;

        if (argc > 1) {
                if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
                        printf("Usage: %s [-h|--help|-t|--only-tty]\n", argv[0]);
                        return 0;
                }
                if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--only-tty") == 0)
                        onlytty = 1;
        }

        if ((win = focusedwin()) == None)
                goto home;
        pid = winpid(win);
        if (!(p = getprocesses(onlytty)))
                goto home;
        if (pid != -1)
                qsort(p->ps, p->n, sizeof(Process), ppidcmp);
        else {
                Process *res = NULL, key;
                XClassHint ch = { NULL, NULL };

                qsort(p->ps, p->n, sizeof(Process), namecmp);
                XGetClassHint(dpy, win, &ch);
                if (ch.res_name) {
                        LOG("main: pidof %s\n", ch.res_name);
                        strncpy(key.name, ch.res_name, sizeof key.name - 1);
                        key.name[sizeof key.name - 1] = '\0';
                        XFree(ch.res_name);
                        if ((res = (Process *)bsearch(&key, p->ps, p->n,
                                                      sizeof(Process), namecmp))) {
                                if (ch.res_class)
                                        XFree(ch.res_class);
                                goto found;
                        }
                }
                if (ch.res_class) {
                        LOG("main: pidof %s\n", ch.res_class);
                        strncpy(key.name, ch.res_class, sizeof key.name - 1);
                        key.name[sizeof key.name - 1] = '\0';
                        XFree(ch.res_class);
                        if ((res = (Process *)bsearch(&key, p->ps, p->n,
                                                      sizeof(Process), namecmp)))
                                goto found;
                }
                goto out;
found:
                pid = res->pid;
                LOG("main: found %s (%ld)\n", res->name, res->pid);
        }
out:
        XCloseDisplay(dpy);
        if (pid == -1 || !deepestchildcwd(p, pid))
                goto home;
        freeprocesses(p);
        return 0;
home:
        freeprocesses(p);
        LOG("%s", "main: falling back to home\n");
        printf("%s\n", getenv("HOME"));
        return 1;
}
