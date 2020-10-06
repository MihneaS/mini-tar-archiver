#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_LINE_LEN 512 // 511 + NULL
#define USERS "usermap.txt"
#define FILES "file_ls"
#define RECORD_SIZE 512
#define FILE_NAME_SIZE 100
#define MOD_SIZE 8
#define ID_SIZE 8
#define SIZE_SIZE 12
#define MTIME_SIZE 12
#define CHKSUM_SIZE 8
#define MAGIC_SIZE 8
#define UGNAME_SIZE 32
#define DEV_SIZE 8
#define PASSWD_SIZE 32

#define nr_of_blocks(n) (n) / RECORD_SIZE + ((n) % RECORD_SIZE ? 1 : 0)

union record {
    char charptr[RECORD_SIZE];
    struct header {
        char name[FILE_NAME_SIZE];
        char mode[MOD_SIZE];
        char uid[ID_SIZE];
        char gid[ID_SIZE];
        char size[SIZE_SIZE];
        char mtime[MTIME_SIZE];
        char chksum[CHKSUM_SIZE];
        char typeflag;
        char linkname[FILE_NAME_SIZE];
        char magic[MAGIC_SIZE];
        char uname[UGNAME_SIZE];
        char gname[UGNAME_SIZE];
        char devmajor[DEV_SIZE];
        char devminor[DEV_SIZE];
    } header;
};

char* parse_usermap_for(char *name, char line[MAX_LINE_LEN], char *delim){
    FILE *users;
    char *w, found_name[UGNAME_SIZE];
    users = fopen(USERS, "r");
    while (fgets(line, MAX_LINE_LEN, users) != NULL) {
        w = strtok(line, delim);
        strcpy(found_name, w);
        if (strcmp(found_name, name ) == 0) {
            break;
        }
    }
    fclose(users); // never move this line after if <=> after return
    if (strcmp(found_name, name) == 0) {
        return line;
    } else {
        fprintf(stderr,
                "my_tar parse_usermap_for(%s): ERROR while parsing usermap.txt "
                "no name %s has been found. returning NULL pointer\n",
                name, name);
        return NULL;
    }

}

void load( char *archvname)
{
    char line[MAX_LINE_LEN], stmp_mod[10], ymd[11], hms[19], gmt[6];
    char lineu[MAX_LINE_LEN], *w, delim[] = ":";
    union record rec = {{0}};
    int tmp, itmp_mod = 0, i, mask, itmp_siz;
    time_t itmp_mtim;
    int itmp_uid, itmp_gid, itmp_chksum;
    struct tm tmp_mtime;
    FILE *files, *archv, *file;

    //openning archive and file_ls
    files = fopen(FILES, "r");
    archv = fopen((const char *) archvname, "w");

    while ( fgets(line, MAX_LINE_LEN, files) != NULL) {
        /*create and print header*/{
            // extracts elements from line from file_ls
            sscanf(line,"%s %d %s %s %d %s %s %s %s\n",
                    stmp_mod, &tmp, rec.header.uname, rec.header.gname,
                    &itmp_siz, ymd, hms, gmt, rec.header.name);

            // calculate mod
            mask = 1;
            for (i = 9; i >= 0; i--) {
                if (strchr("rwx", stmp_mod[i])) {
                    itmp_mod |= mask;
                }
                mask <<=1;
            }
            sprintf(rec.header.mode, "%07o", itmp_mod);

            // exctract size
            sprintf(rec.header.size, "%011o", itmp_siz);

            // calculate epoch time
            sscanf(ymd, "%d-%d-%d", &tmp_mtime.tm_year,
                    &tmp_mtime.tm_mon, &tmp_mtime.tm_mday);
            tmp_mtime.tm_year -= 1900;
            tmp_mtime.tm_mon -= 1;
            sscanf(hms, "%d:%d:%d", &tmp_mtime.tm_hour,
                    &tmp_mtime.tm_min, &tmp_mtime.tm_sec);

            itmp_mtim =  mktime (&tmp_mtime);

            sprintf(rec.header.mtime, "%011o", (int)itmp_mtim);

            // set gid and uid from usermap.txt
            if (parse_usermap_for(rec.header.gname, lineu, delim)) {
                //jump over the password (usually "x" atm of writing)
                w = strtok(NULL, delim);
                //jump over user id
                w = strtok(NULL, delim);
                //get group id
                w = strtok(NULL, delim);
                itmp_gid = atoi(w);
                sprintf(rec.header.gid, "%07o", itmp_gid);
            } else {
                fprintf(stderr, "my_tar load: ERROR while parsing usermap.txt "
                        "no group %s has been found\n"
                        "group id of file %s has not been set",
                        rec.header.gname, rec.header.name);
            }

            if (parse_usermap_for(rec.header.uname, lineu, delim)) {
                //jump over the password (usually "x" atm of writing)
                w = strtok(NULL, delim);
                //get user id
                w = strtok(NULL, delim);
                itmp_uid = atoi(w);
                sprintf(rec.header.uid, "%07o", itmp_uid);
            } else {
                fprintf(stderr, "my_tar load: ERROR while parsing usermap.txt "
                        "no user %s has been found\n"
                        "user id of file %s has not been set",
                        rec.header.uname, rec.header.name);
            }
            // posibila optimizare: retinerea in memorie a unui tabel cu
            // user name, uid si gid si apoi optinerea uid si gid printr-o
            // singura parcurgere a tabelului

            // set constants
            rec.header.typeflag = '0';
            strcpy(rec.header.magic, "GNUtar ");
            memset((void*)rec.header.chksum, ' ', CHKSUM_SIZE);

            // set linkname
            strcpy(rec.header.linkname, rec.header.name);

            // calculate chksum
            itmp_chksum = 0;
            for (i = 0; i < RECORD_SIZE; i++) {
                itmp_chksum += rec.charptr[i];
            }
            sprintf(rec.header.chksum, "%06o", itmp_chksum);
            rec.header.chksum[CHKSUM_SIZE - 1] = ' ';

            // print header
            fwrite(rec.charptr, RECORD_SIZE, 1, archv);
        }

        /*load file content*/{
            file = fopen(rec.header.name, "w");
            memset(rec.charptr, 0, RECORD_SIZE);
            while(fread(rec.charptr, RECORD_SIZE, 1, file)) {
                fwrite(rec.charptr, RECORD_SIZE, 1, archv);
                memset(rec.charptr, 0, RECORD_SIZE);
            }
            fclose(file);
        }
    }
    //print END OF ARCHVIE
    memset(rec.charptr, 0, RECORD_SIZE);
    fwrite(rec.charptr, RECORD_SIZE, 1, archv);
    fwrite(rec.charptr, RECORD_SIZE, 1, archv);

    //closing archive and file_ls
    fclose(files);
    fclose(archv);
}
// posibila optimizare: folosirea  bibliotecii <sys/stat.h>

void list (char *archivename) {
    FILE *archv;
    union record rec;
    int n, read_blocks, size;
    archv = fopen(archivename, "r");

    read_blocks = fread(rec.charptr, RECORD_SIZE, 1, archv);
    while (read_blocks && rec.header.name[0] != '\0') {
        printf("%s\n", rec.header.name);
        sscanf(rec.header.size, "%o", &size);
        n = nr_of_blocks(size) + 1;
        read_blocks = fread(rec.charptr, RECORD_SIZE, n, archv);
    }
}

void get (char *archivename, char *filename) {
    FILE *archv;
    union record rec;
    int n, read_blocks, size, i;
    archv = fopen(archivename, "r");

    //search file in archive
    read_blocks = fread(rec.charptr, RECORD_SIZE, 1, archv);
    while (read_blocks && rec.header.name[0] != '\0' &&
            strcmp(rec.header.name, filename) != 0) {
        sscanf(rec.header.size, "%o", &size);
        n = nr_of_blocks(size) + 1;
        read_blocks = fread(rec.charptr, RECORD_SIZE, n, archv);
    }
    //if file was found
    if (strcmp(rec.header.name, filename) == 0) {
        //print file
        sscanf(rec.header.size, "%o", &size);
        n = nr_of_blocks(size);
        for (i = 0; i < n; ++i) {
            read_blocks = fread(rec.charptr, RECORD_SIZE, 1, archv);
            fwrite(rec.charptr, RECORD_SIZE, 1, stdout);
        }
    } else { // else print error
        fprintf(stderr, "my_tar, get: no file %s in archive %s",
                filename, archivename);
        
    }
}
    
int main() {
    char s[MAX_LINE_LEN], archivename[MAX_LINE_LEN], filename[MAX_LINE_LEN];
    char *w, aux[] = "", delim[] = " "; // w for word
    w=aux;
    while (fgets(s, MAX_LINE_LEN, stdin) && strcmp(w,"quit") != 0) {
        s[strlen(s) - 1] = '\0';
        w = strtok(s, delim);
        if (strcmp(w,"load") == 0) {
            strcpy(archivename, strtok(NULL, delim));
            load(archivename);
        } else if (strcmp(w,"list") == 0) {
            strcpy(archivename, strtok(NULL, delim));
            list(archivename);
        } else if (strcmp(w,"get") == 0) {
            strcpy(archivename, strtok(NULL, delim));
            strcpy(filename, strtok(NULL, delim));
            get(archivename, filename);
        } else if (strcmp(w,"quit") == 0) {
            return 0;
        } else {
            fprintf(stderr, "my_tar, main: invalid command");
        }
    }
    return 0;
}

