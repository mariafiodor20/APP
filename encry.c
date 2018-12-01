#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include "encryption.h"
#include "list.h"

/*global variables*/
static char fileIN[MAX_FILE_NAME];
static char fileOUT[MAX_FILE_NAME];
static char key[BLOCK_SIZE];
static int is_key_set;
static int check_remove;

static void print_usage (void)
{
    printf ("\nHow to use it:\n");
    printf ("    ./encryption [ -k keyfile | -p password ] [ -r ] [ -v ] file\n");
    printf ("    ./decryption [ -k keyfile | -p password ] [ -r ] [ -v ] file\n");
    printf ("\nParameters:\n");
    printf ("    -h usage\n");
    printf ("    -k encryption using a key file\n");
    printf ("    -p encryption using a password\n");
}

Node *add(Node *head, char *val, int encrypted) {
    Node *cursor = head;
    printf("a");
    if(head == NULL) {

        head = malloc(sizeof(Node));
        memset(head->val, 0, BLOCK_SIZE);
        memcpy(head->val, val, BLOCK_SIZE);
        head->next = NULL;
        return head;
    }

    while (cursor->next != NULL) {
        cursor = cursor->next;
    }

    Node *new_node = malloc(sizeof(Node));
    memset(new_node->val, 0, BLOCK_SIZE);
    memcpy(new_node->val, val, BLOCK_SIZE);
    cursor->next = new_node;

    return head;
}

void print(Node *head) {
    while (head != NULL) {
        printf("%s", head->val);
        head = head->next;
    }
}
static void get_encryption_key (char *file_nm)
{
    int fd, keylen;
    unsigned char key_val[BLOCK_SIZE];

    /*open the file*/
    fd = open (file_nm, O_RDONLY);

    /*read the first line in the file*/
    keylen = read(fd, key_val, BLOCK_SIZE);

    if (keylen < 0) {
		perror ("Key failed\n");
		exit (-1);
    }
    else if (keylen == 0) {
		fprintf (stderr, "Key empty\n");
		exit (-1);
    }
    else if (keylen < BLOCK_SIZE) {
		fprintf (stderr, "Warning: the key is shorter than %d bytes\n",
		 BLOCK_SIZE);
    }

    
    memcpy (&key, &key_val, keylen);
    is_key_set = TRUE;

    close (fd);
}

static void parse_option_argument (int opt, char *option_arg)
{
    switch (opt) {
    case NEXT_OPT_KEYFILE:
		get_encryption_key (option_arg);
		break;
    case NEXT_OPT_PASSWORD:
        strncpy ((char *)&key, (char *)option_arg, BLOCK_SIZE);
        is_key_set = TRUE;
		break;
    default:
		fprintf (stderr, "Invalid option argument %s\n", option_arg);
		exit(-1);
		break;
    }
}

static int parse_option (char *option)
{
    switch (option[1]) {
    case 'k':
		return (NEXT_OPT_KEYFILE);
		break;
    case 'p':
		return (NEXT_OPT_PASSWORD);
		break;
    case 'h':
		print_usage ();
		exit (0);
		break;
    default:
		fprintf (stderr, "Invalid option %c\n", option[1]);
		print_usage ();
		exit (-1);
		break;
    }
    return (0);
}

static void parse_cmdline (int argc, char *argv[])
{
    int i;
    int rc;

    for (i = 1; i < argc; i++) {
		if (*argv[i] == '-') {
	    	/*is this an option?*/
	    	rc = parse_option(argv[i]);
	    	if (rc >= 0) {
				if ((i + 1) < argc) {
		    		parse_option_argument (rc, argv[i + 1]);
		    		i++;
				}
				else {
		    		print_usage ();
		    		exit (-1);
				}
	    	}
		}
		else {

	    	strncpy (fileIN, argv[i], MAX_FILE_NAME);
			if(ENC == 1){
	    		strncpy (fileOUT, fileIN, MAX_FILE_NAME);
	    		strcat (fileOUT, ".enc");
			}

			if(DEC == 1){
	    		if (strcmp (fileIN + (strlen (fileIN) - 4), ".enc")) {
					fprintf (stderr, "Input file must end with .enc\n");
					exit (-1);
	    		}
	    		strncpy (fileOUT, fileIN, strlen (fileIN) - 4);
			}
		}
    }
}

/*get the specific header from the file*/
static void get_header (header * hd, int fd) {
    int len;

    /* read the file's header*/
    len = read (fd, hd, sizeof(header));
    if (len == -1) {
		perror ("read header");
		exit(-1);
    }

    /*check the file's header length*/
    if (len != sizeof(header)) {
		fprintf (stderr, "Invalid CRY header length\n");
		exit (-1);
    }

}

/*calculate a checksum so that we keep under control
the files*/
long checksum (char *fname) 
{
    int bytes_read;
    char data_in[BLOCK_SIZE];
    long crc = 0;
    short word;
    int i;
    int fd;

    /*open file*/
    fd = open (fname, O_RDONLY);
    if (fd == -1) {
		perror ("open for checksum failed");
		exit (-1);
    }

    /*first block*/
    bytes_read = read(fd, (void *) data_in, BLOCK_SIZE);

    while (bytes_read > 0) {
        for (i=0; i<bytes_read; i=i+2) {
            /*check if there's an odd number of bytes read*/
            if (i+1 >= bytes_read) {
                word = (data_in[i]<<8)&0xFF00;
            } else {
                word = ((data_in[i]<<8)&0xFF00) + (data_in[i+1]&0xFF);
            }
            crc = crc + (long) word;
        }
        
        /*next block*/
        bytes_read = read(fd, data_in, BLOCK_SIZE);
    }

    return crc;
}

/*building the specific header for the output file*/
static int build_header (int fd_in, int fd_out)
{
  	struct stat fs;
    header head;
    int word_count;
    int rc;

    /*size of file*/
    rc = fstat (fd_in, &fs);
 
    /*build the header from scratch*/
    head.magic = CRY_MAGIC;
    head.enc_type = GCRY_CIPHER_AES256;
    head.file_len = fs.st_size;
    head.major = MAJOR_VER;
    head.minor = MINOR_VER;
    head.crc = checksum(fileIN);

    /*write the header to the output file*/
    word_count = write(fd_out, &head, sizeof (header));
    if (word_count == -1) {
		perror ("write failed");
		exit (-1);
    }

    return head.file_len;
}


static void encrypt_file (char *key)
{
    char key_aux[BLOCK_SIZE];
    char *data_in;
    char *data_out;
    int fd_in, fd_out;
    int wrote, encrypted;
    gcry_error_t err = 0;
    gcry_cipher_hd_t handler;
    header hd;
    int bytes_processed = 0;

    Node *list = NULL;

    memcpy (key_aux, key, BLOCK_SIZE);

    fd_in = open (fileIN, O_RDONLY);
    if (fd_in == -1) {
		perror ("open of input file failed");
		exit (-1);
    }
    
    /*if the file needs to be encrypted*/
    if(ENC == 1){
	    /*open the output file*/
	    fd_out = open (fileOUT, O_RDWR | O_CREAT | O_EXCL, 0644);
	    if (fd_out == -1) {
			perror ("couldn't open output file");
			exit(-1);
	    }

	    hd.file_len = build_header(fd_in, fd_out);
	}

	/*if the file needs to be decrypted*/
	if(DEC == 1){
	    get_header (&hd, fd_in);
	    if (hd.file_len <= 0) {
			fprintf (stderr, "file is empty\n");
			exit (-1);
	    }
	    /*open the output file*/
	    fd_out = open (fileOUT, O_WRONLY | O_CREAT | O_EXCL, 0644);
	    
	}


    /*open an encryption context handle*/
    err = gcry_cipher_open (&handler, GCRY_CIPHER_AES256,
			    GCRY_CIPHER_MODE_CBC, 0);
    if (err) {
		fprintf (stderr, "failed: %s/%s\n",
		 gcry_strsource (err), gcry_strerror (err));
    }

    err = gcry_cipher_setkey (handler, key, 32);
    if (err) {
		fprintf (stderr, "setkey fail: %s/%s\n",
		 gcry_strsource (err), gcry_strerror (err));
    }


    char *all_data = calloc(hd.file_len, sizeof(char));

    //memset (data_in, 0, BLOCK_SIZE);
    data_in = calloc(BLOCK_SIZE, sizeof(char));

    encrypted = read (fd_in, data_in, BLOCK_SIZE);
    long index = 0;

    while (encrypted > 0) {
        // data_in[BLOCK_SIZE] = '\0';

        memcpy(all_data + index, data_in, encrypted);
        //memset (data_in, 0, BLOCK_SIZE);

        encrypted = read (fd_in, data_in, BLOCK_SIZE);
        index += encrypted;
    }

    char *encrypted_data = calloc(hd.file_len, sizeof(char));

    //printf("%s\n", all_data);
    char *aux = NULL;

    for(int i = 0; i < hd.file_len; i += BLOCK_SIZE) {
        aux = calloc(sizeof(char),  BLOCK_SIZE);
        strncpy(aux, all_data + i, BLOCK_SIZE);

        printf("%s\n", aux);
        //memset (data_out, 0, BLOCK_SIZE);
        data_out = calloc(BLOCK_SIZE, sizeof(unsigned char));

        if(ENC == 1){
            err = gcry_cipher_encrypt (handler,
                (unsigned char *) data_out,
                BLOCK_SIZE ,
                (const unsigned char *) aux, 
                BLOCK_SIZE );
        }

        if(DEC == 1){
            err = gcry_cipher_decrypt (handler,
                (unsigned char *) data_out,
                BLOCK_SIZE,
                (const unsigned char *) aux,
                BLOCK_SIZE);
        }

        if (err) {
            fprintf (stderr, "encrypt Failure: %s/%s\n",
            gcry_strsource (err), gcry_strerror (err));
        }

        strncpy(encrypted_data + i, data_out, BLOCK_SIZE);
        //memcpy(encrypted_data + i, data_out, BLOCK_SIZE);
    }

    wrote = write (fd_out, encrypted_data, hd.file_len);

        if (wrote == -1) {
            perror ("write failed");
            exit (-1);
        }

    /*while (encrypted > 0) {
		memset (data_out, 0, BLOCK_SIZE);

		if(ENC == 1){
			err = gcry_cipher_encrypt (handler,
					(unsigned char *) data_out,
					BLOCK_SIZE,
					(const unsigned char *) data_in,
					BLOCK_SIZE);
		}

		if(DEC == 1){
			err = gcry_cipher_decrypt (handler,
					(unsigned char *) data_out,
					BLOCK_SIZE,
					(const unsigned char *) data_in,
					BLOCK_SIZE);
		}

		if (err) {
		    fprintf (stderr, "encrypt Failure: %s/%s\n",
			     gcry_strsource (err), gcry_strerror (err));
		}

		//write the decrypted data out
		wrote = write (fd_out, data_out , encrypted);
		if (wrote == -1) {
		    perror ("write failed");
		    exit (-1);
		}

		//keep track of how many bytes we've processed 
		bytes_processed += encrypted;

	
		memset (data_in, 0, BLOCK_SIZE);
		encrypted = read (fd_in, data_in, BLOCK_SIZE);
    }*/

    gcry_cipher_close (handler);

    if (close(fd_in)) {
        perror ("close input file");
        exit (-1);
    }
    if (close (fd_out)) {
		perror ("close output file");
		exit (8);
    }


	if(DEC == 1){
	    //check if the checksum matched
	    if (hd.crc != checksum(fileOUT)) {
		  fprintf (stderr, "Warning: checksum mismatched.\n");
	    }
	}
}



int main (int argc, char *argv[])
{
    clock_t begin = clock();

    if (argc <= 1) {
		printf("not enough parameters\n");
		exit (-1);
    }

    memset (key, 0, BLOCK_SIZE);
    is_key_set = FALSE;
    check_remove = FALSE;

    parse_cmdline (argc, argv);
    
    if (!is_key_set) {
	printf ("\nNo key\n");
        exit(0);
    }
    if (strlen (key) < BLOCK_SIZE) {
        fprintf(stderr, "Warning: the key is shorter than %d bytes\n",
                BLOCK_SIZE);
    }

    encrypt_file (key);

    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("time spent:%f\n", time_spent);

    /*Node *node = NULL;

    node = add(node, "abc");
    node = add(node, "def");

    print(node);
*/
    return 0;
}
