#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <X11/Xlib.h>

#define DEBUG                           0

#define LOG(fmt, ...)                   do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define STR_HELPER(X)                   #X
#define STR(X)                          STR_HELPER(X)

#define DEVPTS                          "/dev/pts"
#define PWD                             "PWD="

#define XA_CARDINAL                     (XInternAtom(dpy, "CARDINAL", False))
#define XA_WM_PID                       (XInternAtom(dpy, "_NET_WM_PID", False))

typedef struct {
        long pid;
        long ppid;
} Process;

typedef struct {
        Process *ps;
        size_t n;
} Processes;

static void cleanup(Processes *p);
static int deepestchildcwd(Processes *p, long pid);
static Window focusedwin();
static Processes *getprocesses();
static int istty(long pid);
static int ppidcmp(const void *p1, const void *p2);
static int printcwd(Process *ps);
static int printlcwd(long pid);
static int printpcwd(long pid);
static long winpid(Window win);

int logical = 0;
int ttyonly = 0;
Display *dpy;

void
cleanup(Processes *p)
{
        XCloseDisplay(dpy);
        free(p->ps);
        free(p);
}

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

Processes *
getprocesses()
{
        unsigned int i, j;
        glob_t globbuf;
        Processes *p = NULL;

        glob("/proc/[0-9]*", GLOB_NOSORT, NULL, &globbuf);
        p = malloc(sizeof(Processes));
        p->ps = malloc(globbuf.gl_pathc * sizeof(Process));

        for (i = j = 0; i < globbuf.gl_pathc; i++) {
                char d, path[32], line[64];
                char *b;
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
                if (ttyonly && !istty(p->ps[j].pid)) {
                        LOG("getprocesses: skipping %ld, not a tty process\n",
                                        p->ps[j].pid);
                        continue;
                }
                b = strrchr(line, ')');
                p->ps[j].ppid = atol(b + 4);
                LOG("getprocesses: found pid = %6ld, ppid = %6ld\n",
                                p->ps[j].pid, p->ps[j].ppid);
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
ppidcmp(const void *p1, const void *p2)
{
        return ((Process *)p1)->ppid - ((Process *)p2)->ppid;
}

int
printcwd(Process *ps)
{
        if (!logical || !printlcwd(ps->pid))
                return printpcwd(ps->pid);
        return 1;
}

int
printlcwd(long pid)
{
        char path[64];
        char *c;
        char *line = NULL;
        size_t d;
        ssize_t rd;
        FILE *fp;
        struct stat buf;

        snprintf(path, sizeof path , "/proc/%ld/environ", pid);
        if (!(fp = fopen(path, "r"))) {
                LOG("printlcwd: reading %s failed\n", path);
                return 0;
        }
        if ((rd = getline(&line, &d, fp)) == -1) {
                fclose(fp);
                free(line);
                LOG("printlcwd: getline failed on %s\n", path);
                return 0;
        }
        fclose(fp);
        c = line;
        while (strncmp(c, PWD, sizeof PWD - 1) != 0) {
                c = strchr(c, '\0');
                if (c - line >= rd) {
                        free(line);
                        return 0;
                }
                c++;
        }
        c += sizeof PWD - 1;
        if (stat(c, &buf) == -1 || !S_ISDIR(buf.st_mode)) {
                LOG("printlcwd: %s is not a directory\n", c);
                free(line);
                return 0;
        }
        printf("%s\n", c);
        free(line);
        return 1;
}

int
printpcwd(long pid)
{
        char path[32];
        char *cwd;
        ssize_t rd, sz = 256;
        struct stat buf;

        snprintf(path, sizeof path , "/proc/%ld/cwd", pid);

        for(cwd = NULL; ; sz *= 2) {
                cwd = realloc(cwd, sz);
                rd = readlink(path, cwd, sz);
                if (rd == -1) {
                        LOG("printpcwd: readlink %s failed\n", path);
                        free(cwd);
                        return 0;
                } else if (rd < sz)
                        break;
                sz *= 2;
        }
        cwd[rd] = '\0';
        if (stat(cwd, &buf) == -1 || !S_ISDIR(buf.st_mode)) {
                LOG("printpcwd: %s is not a directory\n", cwd);
                free(cwd);
                return 0;
        }
        printf("%s\n", cwd);
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

        if (XGetWindowProperty(dpy, win, XA_WM_PID, 0L, 1L, False, XA_CARDINAL,
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
        long pid;
        Window win;
        Processes *p = NULL;

        if (argc == 2)
                if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
                        printf("Usage:\n"
                               "	%1$s [-h|--help]\n"
                               "	%1$s [-p|--physical] [-l|--logical]"
                                           " [-a|--all] [-t|--tty-only]\n", argv[0]);
                        return 0;
                }
        while (argc > 1) {
                if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--logical") == 0)
                        logical = 1;
                else if (strcmp(argv[1], "-t") == 0 || strcmp(argv[1], "--tty-only") == 0)
                        ttyonly = 1;
                else if (strcmp(argv[1], "-p") == 0 || strcmp(argv[1], "--physical") == 0)
                        logical = 0;
                else if (strcmp(argv[1], "-a") == 0 || strcmp(argv[1], "--all") == 0)
                        ttyonly = 0;
                argc--, argv++;
        }
        if ((win = focusedwin()) == None)
                goto home;
        if ((pid = winpid(win)) == -1)
                goto home;
        if (!(p = getprocesses()))
                goto home;
        qsort(p->ps, p->n, sizeof(Process), ppidcmp);
        if (pid == -1 || !deepestchildcwd(p, pid))
                goto home;
        cleanup(p);
        return 0;
home:
        LOG("%s", "main: falling back to home\n");
        printf("%s\n", getenv("HOME"));
        cleanup(p);
        return 1;
}
