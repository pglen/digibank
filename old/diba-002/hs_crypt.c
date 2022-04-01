// HS crypt block loop

static void hs_encrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;
    
    for(loop = 0; loop < size2; loop += 1024)
        {
        bluepoint2_encrypt(pmem, 1024, pass, plen);
        pmem += 1024;
        }
}

static void hs_decrypt(void *mem, int size2, void *pass, int plen)

{
    int loop; char *pmem = (char*)mem;
    
    for(loop = 0; loop < size2; loop += 1024)
        {
        bluepoint2_decrypt(pmem, 1024, pass, plen);
        pmem += 1024;
        }
}



