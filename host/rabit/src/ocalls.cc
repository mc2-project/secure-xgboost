
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <xgboost/c_api.h>
#include <vector>
#include <dmlc/io.h>
#include <cstring>

#include "xgboost_u.h"

extern "C" {
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
}

void host_helloworld() {
	//fprintf(stdout, "Enclave called into host to print: Hello World!\n");
}

int host_rabit__GetRank() {
    //fprintf(stdout, "Ocall: rabit::GetRank\n");
	return ocall_rabit__GetRank();
}

int host_rabit__GetWorldSize() {
    //fprintf(stdout, "Ocall: rabit::GetWorldSize\n");
	return ocall_rabit__GetWorldSize();
}

int host_rabit__IsDistributed() {
    //fprintf(stdout, "Ocall: rabit::IsDistributed\n");
    return ocall_rabit__IsDistributed();
}

DIR* host_opendir(char* path) {
    //fprintf(stdout, "Ocall: opendir\n");
    return opendir(path);
}

struct stat host_stat(char* path) {
    //fprintf(stdout, "Ocall: stat\n");
    struct stat sb;
    if (stat(path, &sb) == -1) {
      int errsv = errno;
      LOG(FATAL) << "LocalFileSystem.GetPathInfo: "
        << path << " error: " << strerror(errsv);
    }
    return sb;
}

FILE* host_fopen(char* fname, char* flag) {
    //fprintf(stdout, "Ocall: fopen\n");
    FILE* fp;
#if DMLC_USE_FOPEN64
    fp = fopen64(fname, flag);
#else  // DMLC_USE_FOPEN64
    fp = fopen(fname, flag);
#endif  // DMLC_USE_FOPEN64
    return fp;
}

void host_fclose(FILE* fp) {
  //fprintf(stdout, "Ocall: fclose\n");
  std::fclose(fp);
}

FILE* host_fseek(FILE* fp, long pos) {
  //fprintf(stdout, "Ocall: fseek\n");
#ifndef _MSC_VER
  CHECK(!std::fseek(fp, pos, SEEK_SET));  // NOLINT(*)
#else  // _MSC_VER
  CHECK(!_fseeki64(fp, pos, SEEK_SET));
#endif  // _MSC_VER
  return fp;
}

// Buffer should be freed by caller
void* host_fread_one(FILE* fp, size_t size) {
  //fprintf(stdout, "Ocall: fread\n");
  char* buffer = (char*) malloc (sizeof(char)*size);
  int n = std::fread(buffer, 1, size, fp);
  return buffer;
}

void host_fwrite_one(void* buffer, size_t count, FILE* fp) {
  //fprintf(stdout, "Ocall: fwrite\n");
  CHECK(std::fwrite(const_cast<const void*> (buffer), 1, count, fp) == count) << "FileStream.Write incomplete";
}

//std::vector<dmlc::io::FileInfo>* host_opendir_and_readdir(char* path) {
void* host_opendir_and_readdir(char* path) {
    //fprintf(stdout, "Ocall: opendir_and_readdir\n");
    DIR *dir = opendir(path);
    if (dir == NULL) {
      int errsv = errno;
      LOG(FATAL) << "LocalFileSystem.ListDirectory " << path
                 <<" error: " << strerror(errsv);
    }
    struct dirent *ent;
    std::vector<char*>* out_list = new std::vector<char*>;
    while ((ent = readdir(dir)) != NULL) {
      if (!strcmp(ent->d_name, ".")) continue;
      if (!strcmp(ent->d_name, "..")) continue;
      out_list->push_back(ent->d_name);
    }
    closedir(dir);
    return (void*)out_list;
}
