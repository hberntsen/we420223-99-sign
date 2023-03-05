#include <stdio.h>
#include <string.h>
#include "rsaeuro.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include "dat.h"

R_RANDOM_STRUCT random_state;
char random_block[1];

off_t get_file_size(FILE* __stream) {
    struct stat sb;
    int err;
    int fn = fileno(__stream);
    err = fstat(fn, &sb);
    if(err) {
        puts("can not get file size");
        return 0;
    }
    else {
        return sb.st_size;
    }
}


R_RSA_PRIVATE_KEY PRIVATE_KEY;

// Param 1: 
// - 0x38 bytes envelope
// - 0x40 encryptedKey
// - 8 bytes iv
void open_envelope(unsigned char* param_1, unsigned char* out) 
{
    int out_offset;
    int status;
    unsigned char *pcVar2;
    unsigned int partOutLen;
    unsigned char iv[8];
    unsigned char partIn[24];
    unsigned char partOut[32];

    unsigned char encryptedKey[128];
    R_ENVELOPE_CTX context;

    printf("in before: \n");
    for(int i=0;i < 0x80; i++) {
        printf("0x%x ", param_1[i]);
    }
    puts("");

    memcpy(encryptedKey, param_1 + 0x38, 0x40);
    memcpy(iv, param_1 + 0x78, 8);
    status = R_OpenInit(&context, 3, encryptedKey, 0x40, iv, &PRIVATE_KEY);
    if (status == 0) {
        out_offset = 0;
        pcVar2 = param_1;
        do {
            memcpy(partIn, pcVar2, 0x18);
            status = R_OpenUpdate(&context, partOut, &partOutLen, partIn, 0x18);
            printf("Out: ");
            for(int i=0;i < partOutLen; i++) {
                printf("0x%x ", partOut[i]);
            }
            printf("\n");
            if(status != 0)
                goto open_envelope_fail;
            pcVar2 += 0x18;
            memcpy(out + out_offset, partOut, partOutLen);
            out_offset += partOutLen;
        } while(pcVar2 != param_1 + 0x30);
        memcpy(partIn, param_1 + 0x30, 8);
        status = R_OpenUpdate(&context, partOut, &partOutLen, partIn, 8);
        printf("Out last: ");
        for(int i=0;i < partOutLen; i++) {
            printf("0x%x ", partOut[i]);
        }
        printf("\n");
        if(status != 0)
            goto open_envelope_fail;
        memcpy(out + out_offset, partOut, partOutLen);
        out_offset += partOutLen;

        status = R_OpenFinal(&context, partOut, &partOutLen);
        if(status == 0) {
            memcpy(out + out_offset, partOut, partOutLen);
            puts("Rsa_thing done no error");
        }
        else 
            goto open_envelope_fail;
    } 
    return;
open_envelope_fail:
    fprintf(stderr, "%s fail: %d\n", __func__, status);
}

int verify_firmware_signature(char* path) {
    FILE *__stream;
    off_t __size;
    int err;
    char *error_message = "";
    unsigned char *firmware_buf;
    const char* private_keys[6] = {
        DAT_0041d784,
        DAT_0041d4c0,
        DAT_0041d1fc,
        DAT_0041cf38,
        DAT_0041cc74,
        DAT_0041c9b0
    };
    unsigned char opened_envelope[200];
    unsigned char auStack_144[272];

    unsigned char calculated_sha1[20];

    memset(opened_envelope, 0, 200);
    puts("verify firmware start");
    memset(auStack_144,0,0x110);
    __stream = fopen(path, "r");
    if(__stream == 0){
        fprintf(stderr, "[%s] can not open file \"%s\"!\n",__func__,error_message);
    }
    else {
        __size = get_file_size(__stream);
        if(__size) {
            firmware_buf = malloc(__size);
            if(firmware_buf == 0) {
                fprintf(stderr,"[%s] malloc err.\n","verify_firmware_signature");
            }
            else {
                memset(firmware_buf,0,__size);
                err = fread(firmware_buf,1,__size + 1,__stream);
                if (err == 0) {
                    fprintf(stderr,"[%s] fread failure or file \"%s\" too large\n", __func__ , error_message);
                }
                else {
                    fprintf(stderr,"[%s] read [%lld] bytes form file \"%s\".\n", __func__, (long long int)__size, path);
                    fclose(__stream);
                    __stream = 0;
                    if( firmware_buf[0] == ']' &&
                        firmware_buf[1] == 'C' &&
                        firmware_buf[2] == 'o' &&
                        firmware_buf[3] == 't') {
                        if(__size < ((int*)firmware_buf)[1] + 0x110U) {
                            error_message = "[%s] no signature.\n";
                        }
                        else {
                            uint32_t auStack_144_offset=((int*)firmware_buf)[1];
                            printf("auStack_144 offset: %x\n", auStack_144_offset);
                            /*memcpy(auStack_144,(void *)((size_t)firmware_buf + ((int*)firmware_buf)[1]),0x110);*/
                            memcpy(auStack_144,&firmware_buf[auStack_144_offset],0x110);
                            if (((auStack_144[268] == 'H') && (auStack_144[269] == 'D')) &&
                                ((auStack_144[270] == 'R' && (auStack_144[271] == '0')))) {
                                const uint32_t key_index = ((uint32_t*)auStack_144)[2];
                                const uint32_t second_sha_size = ((uint32_t*)auStack_144)[1];
                                printf("2nd_sha_size: %u\n", second_sha_size);
                                if(key_index < 7) {
                                    memcpy((void*)&PRIVATE_KEY, DAT_0041d784, 0x2c2);
                                    memset(opened_envelope, 0, 200);
                                    open_envelope(auStack_144 + 0x8c, opened_envelope);
                                    SHA1((unsigned char*)auStack_144, 0x8c, calculated_sha1);
                                    for(int i=0; i< 20; i++) {
                                        if(calculated_sha1[i] != opened_envelope[i]) {
                                            error_message = "[%s] header unequal.\n";
                                            goto err;
                                        }
                                    }
                                    // Index 1 is already loaded
                                    if(key_index != 1) {
                                        memcpy((void*)&PRIVATE_KEY, private_keys[key_index - 1], 0x2c2);
                                    }
                                    memset(opened_envelope, 0, 200);
                                    open_envelope(&auStack_144[0xc], opened_envelope);
                                    SHA1(firmware_buf, second_sha_size, calculated_sha1);
                                    for(int i=0; i < 20; i++) {
                                        if(calculated_sha1[i] != opened_envelope[i]) {
                                            error_message = "[%s] region unequal.\n";
                                            goto err;
                                        }
                                    }
                                    fprintf(stderr, "[%s] verify firmware finish.\n", __func__);
                                    free(firmware_buf);
                                    return 0;
                                } else {
                                    error_message = "[%s] Wrong key index or no signature.\n";
                                }
                            } else {
                                error_message = "[%s] can not find signature magic number.\n";
                            }
                        }
                    } else {
                        error_message = "[%s] wrong image file.\n";
                    }
                }
            }
        }
        fprintf(stderr,"[%s] The firmware file is too small!\n","verify_firmware_signature");
    }
err:
    fprintf(stderr, error_message, __func__);
    R_RandomFinal(&random_state);
    fprintf(stderr, "[%s] verify firmware fail.\n", __func__);
    if(__stream != 0) {
        fclose(__stream);
    }
    if(firmware_buf != 0) {
        free(firmware_buf);
    }
    return -1;
}

int seal_envelope(unsigned char in[20], unsigned char* out) {
    R_ENVELOPE_CTX context;
    R_RSA_PUBLIC_KEY publicKey;
    R_RSA_PUBLIC_KEY *publicKeys[1] = { &publicKey };
    unsigned char iv[8] = {0};
    unsigned char encryptedKey[MAX_ENCRYPTED_KEY_LEN] = {0};
    unsigned char *encryptedKeys[1] = { encryptedKey };
    unsigned int encryptedKeyLen; 
    unsigned int partOutLen = 0; 
    int status;
    unsigned char dataIn[48] = {0};

    memcpy(dataIn, in, 20);
    memcpy(&publicKey, DAT_0041d784, sizeof(R_RSA_PUBLIC_KEY));

    printf("out before: \n");
    for(int i=0;i < 0x80; i++) {
        printf("0x%x ", out[i]);
    }
    puts("");

    printf("dataIn: \n");
    for(int i=0;i < sizeof dataIn; i++) {
        printf("0x%x ", dataIn[i]);
    }
    puts("");

    status = R_SealInit(&context, encryptedKeys, &encryptedKeyLen, iv, 1, &publicKeys, 3, &random_state);
    if(status) {
        fprintf(stderr, "seal init error: %i", status);
        return -1;
    }

    status = R_SealUpdate(&context, out, &partOutLen, dataIn, sizeof dataIn);
    if(status) {
        fprintf(stderr, "seal update error: %i", status);
        return -2;
    }
    printf("partOutLen: %x\n", partOutLen);

    status = R_SealFinal(&context, out + partOutLen, &partOutLen);
    if(status) {
        fprintf(stderr, "seal final error: %i", status);
        return -3;
    }
    printf("partOutLen: %x\n", partOutLen);

    memcpy(out + 0x38, encryptedKey, 0x40);
    memcpy(out + 0x78, iv, 8);
    printf("written to out: \n");
    for(int i=0;i < 0x80; i++) {
        printf("0x%x ", out[i]);
    }
    puts("");

    return 0;
}

int sign(char* path_in, char* path_out) {
    FILE *firmware_in;
    FILE *firmware_out;
    unsigned char* firmware_buf;
    off_t firmware_size;
    char* error_message;
    unsigned char* auStack_144;
    unsigned char calculated_sha1[20];

    firmware_in = fopen(path_in, "r");
    if(!firmware_in) {
        fprintf(stderr, "Cannot open firmware in\n");
        return -1;
    }
    firmware_out = fopen(path_out, "w");
    if(!firmware_out) {
        fprintf(stderr, "Cannot open firmware out(%s)\n", path_out);
        return -2;
    }

    firmware_size = get_file_size(firmware_in);
    if(!firmware_size) {
        fprintf(stderr, "firmware in size err\n");
        return -3;
    }

    firmware_buf = malloc(firmware_size);
    if(!firmware_buf) {
        fprintf(stderr, "firmware malloc error\n");
        return -4;
    }

    {
        size_t bytes_read = fread(firmware_buf,1, firmware_size, firmware_in);
        if(bytes_read != firmware_size) {
            fprintf(stderr, "firmware read error: %lu\n", bytes_read);
            free(firmware_buf);
            return -4;
        }
    }

    if( firmware_buf[0] == ']' &&
        firmware_buf[1] == 'C' &&
        firmware_buf[2] == 'o' &&
        firmware_buf[3] == 't') {
        if(firmware_size < ((int*)firmware_buf)[1] + 0x110U) {
            error_message = "no signature.\n";
            goto done;
        }
        uint32_t auStack_144_offset=((int*)firmware_buf)[1];
        printf("auStack_144 offset: %x\n", auStack_144_offset);
        auStack_144 = &firmware_buf[auStack_144_offset];
        if (((auStack_144[268] == 'H') && (auStack_144[269] == 'D')) &&
            ((auStack_144[270] == 'R' && (auStack_144[271] == '0')))) {
            const uint32_t key_index = 1;
            const uint32_t second_sha_size = auStack_144_offset;

            memcpy(&auStack_144[4], &second_sha_size, 4);
            memcpy(&auStack_144[8], &key_index, 4);

            SHA1(firmware_buf, second_sha_size, calculated_sha1);
            if(seal_envelope(calculated_sha1, auStack_144 + 0xc)) {
                error_message = "seal envelope 2 fail\n";
                goto done;
            }

            SHA1(auStack_144, 0x8c, calculated_sha1);
            if(seal_envelope(calculated_sha1, auStack_144 + 0x8c)) {
                error_message = "seal envelope 1 fail\n";
                goto done;
            }

            if(fwrite(firmware_buf, 1, firmware_size, firmware_out) != firmware_size) {
                error_message = "could not write firmware";
                goto done;
            }
        } else {
            error_message = "can not find signature magic number.\n";
            goto done;
        }

    }

done:
    if(error_message) {
        fprintf(stderr, error_message);
    }

    free(firmware_buf);
    if(error_message) {
        return -100000;
    }
    return 0;
}

void init_random() { 
    int random_bytes_needed;
    R_RandomInit(&random_state);
    while(R_GetRandomBytesNeeded(&random_bytes_needed, &random_state) != 0) {
        R_RandomUpdate(&random_state, random_block, 1);
    }
    R_RandomCreate(&random_state);
}

void usage(char* prog) {
    puts("Usage:");
    printf("%s v FILE: verify a file\n", prog);
    printf("%s s FILE_IN FILE_OUT: sign a file\n", prog);
}

int main(int argc, char* argv[]) {

    if(argc < 3) {
        usage(argv[0]);
    } else if(argv[1][0] == 'v' && argc == 3) {
        init_random();
        verify_firmware_signature(argv[2]);
        R_RandomFinal(&random_state);
    } else if(argv[1][0] == 's' && argc == 4) {
        init_random();
        sign(argv[2], argv[3]);
        R_RandomFinal(&random_state);
    } else {
        usage(argv[0]);
    }

    return 0;
}
