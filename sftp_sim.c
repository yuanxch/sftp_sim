#include "libssh2_config.h"
#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<string.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>


/**
 * ssh配置
 */
struct ssh_struct
{	
	char *source;
	char *target;	

	char *host;
	char *user;
	char *pass;
} ssh_conf;


int main(int argc, char *argv[])
{
	int c, ssh_errno;

	while ((c = getopt(argc, argv, "h:u:p:s:t:H")) != -1) {
		switch(c) {
			case 'h':
				ssh_conf.host = strdup(optarg);
				break;
			case 'u':
				ssh_conf.user = strdup(optarg);
				break;
			case 'p':
				ssh_conf.pass = strdup(optarg);
				break;
			case 's':
				ssh_conf.source = strdup(optarg);
				break;
			case 't':
				ssh_conf.target = strdup(optarg);
				break;
			case 'H':
			default:
				show_help();
				return 1;
		}
	}

	/* 判断是否加了必填参数 -x */
	if (ssh_conf.host == NULL) {
		show_help();
		fprintf(stderr, "Attention: Please use the indispensable argument: -h <host>\n\n");		
		exit(1);
	}	


	ssh_errno = sftp_w(&ssh_conf);

	printf("errno:%d\thost:%s\tuser:%s\tpass:%s\tsource:%s\ttarget:%s\n", ssh_errno, ssh_conf.host, ssh_conf.user, ssh_conf.pass, ssh_conf.source, ssh_conf.target);

	return 0;
}

int show_help()
{

	char *b = "--------------------------------------------------------------------------------------------------\n"
		   "-h <host>	remote host\n"
		   "-u <user>	remote host user account\n"
		   "-p <password>	remote host user password\n"		   
		   "-s <source>	which file will be translated\n"
		   "-t <target>	which file file will be saved as\n"
		   "-H <help>	print this help and exit\n\n"
		   "\n";
	fprintf(stderr, b, strlen(b));
	return 0;
}


/** 
 * 远程读文件
 */
int scp_r(struct ssh_struct * conf)
{

    unsigned long hostaddr;
    int sock, i, auth_pw = 1;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    const char *username = conf->user;
    const char *password = conf->pass;
    const char *loclfile = conf->source;
    const char *scppath = conf->target;
    struct stat fileinfo;

    int handle;
    int rc;
    off_t got = 0;
    int errorno = 0;

#ifdef WIN32
    WSADATA wsadata;

    WSAStartup(MAKEWORD(2, 0), &wsadata);
#endif

    hostaddr = inet_addr(conf->host);
    rc = libssh2_init(0);
    if (rc != 0) {
	fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
	return 1;
    }

    handle =
	open(loclfile, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
    if (-1 == handle) {
	fprintf(stderr, "Can't open local file %s\n", loclfile);
	return 2;
    }


    /* Ultra basic "connect to port 22 on localhost"
     * Your code is responsible for creating the socket establishing the
     * connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr *) (&sin),
		sizeof(struct sockaddr_in)) != 0) {
	fprintf(stderr, "failed to connect!\n");
	return 3;
    }

    /* Create a session instance
     */
    session = libssh2_session_init();
    if (!session)
	return 4;

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(session, sock);
    if (rc) {
	fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
	return 5;
    }

    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for (i = 0; i < 20; i++) {
	fprintf(stderr, "%02X ", (unsigned char) fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if (auth_pw) {
	/* We could authenticate via password */
	if (libssh2_userauth_password(session, username, password)) {
	    fprintf(stderr, "Authentication by password failed.\n");
	    errorno = 6;
	    goto shutdown;
	}
    } else {
	/* Or by public key */
	if (libssh2_userauth_publickey_fromfile(session, username,
						"/home/username/.ssh/id_rsa.pub",
						"/home/username/.ssh/id_rsa",
						password)) {
	    fprintf(stderr, "\tAuthentication by public key failed\n");
	    errorno = 7;
	    goto shutdown;
	}
    }

    /* Request a file via SCP */
    channel = libssh2_scp_recv(session, scppath, &fileinfo);

    if (!channel) {
	fprintf(stderr, "Unable to open a session: %d\n",
		libssh2_session_last_errno(session));
	errorno = 8;
	goto shutdown;
    }


    while (got < fileinfo.st_size) {
	char mem[40960];
	int amount = sizeof(mem);

	if ((fileinfo.st_size - got) < amount) {
	    amount = fileinfo.st_size - got;
	}

	rc = libssh2_channel_read(channel, mem, amount);
	if (rc > 0) {
	    write(handle, mem, rc);
	} else if (rc < 0) {
	    fprintf(stderr, "libssh2_channel_read() failed: %d\n", rc);
	    break;
	}
	got += rc;
    }

    libssh2_channel_free(channel);
    channel = NULL;
    close(handle);

  shutdown:

    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    fprintf(stderr, "all done\n");

    libssh2_exit();

    return errorno;
}

/*远程写文件*/
int sftp_w(struct ssh_struct *conf)
{

    unsigned long hostaddr;
    int sock, i, auth_pw = 1;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    const char *username = conf->user;
    const char *password = conf->pass;
    const char *loclfile = conf->source;
    const char *sftppath = conf->target;
    int rc;
    FILE *local;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    char mem[1024 * 100];
    size_t nread;
    char *ptr;
    int errorno = 0;


#ifdef WIN32
    WSADATA wsadata;

    WSAStartup(MAKEWORD(2, 0), &wsadata);
#endif

    hostaddr = inet_addr(conf->host);
    rc = libssh2_init(0);

    if (rc != 0) {
	fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
	return 1;
    }

    local = fopen(loclfile, "rb");
    if (!local) {
	fprintf(stderr, "Can't open local file %s\n", loclfile);
	return 2;
    }

    /*
     * The application code is responsible for creating the socket
     * and establishing the connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr *) (&sin),
		sizeof(struct sockaddr_in)) != 0) {
	fprintf(stderr, "failed to connect!\n");
	return 3;
    }

    /* Create a session instance
     */
    session = libssh2_session_init();

    if (!session)
	return 4;

    /* Since we have set non-blocking, tell libssh2 we are blocking */
    libssh2_session_set_blocking(session, 1);


    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(session, sock);

    if (rc) {
	fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
	return 5;
    }

    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

    fprintf(stderr, "Fingerprint: ");
    for (i = 0; i < 20; i++) {
	fprintf(stderr, "%02X ", (unsigned char) fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if (auth_pw) {
	/* We could authenticate via password */
	if (libssh2_userauth_password(session, username, password)) {

	    fprintf(stderr, "Authentication by password failed.\n");
	    errorno = 6;
	    goto shutdown;
	}
    } else {
	/* Or by public key */
	if (libssh2_userauth_publickey_fromfile(session, username,
						"/home/username/.ssh/id_rsa.pub",
						"/home/username/.ssh/id_rsa",
						password)) {
	    fprintf(stderr, "\tAuthentication by public key failed\n");
	    errorno = 7;
	    goto shutdown;
	}
    }

    fprintf(stderr, "libssh2_sftp_init()!\n");

    sftp_session = libssh2_sftp_init(session);


    if (!sftp_session) {
	fprintf(stderr, "Unable to init SFTP session\n");
	errorno = 8;
	goto shutdown;
    }

    fprintf(stderr, "libssh2_sftp_open()!\n");

    /* Request a file via SFTP */
    sftp_handle =
	libssh2_sftp_open(sftp_session, sftppath,
			  LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT |
			  LIBSSH2_FXF_TRUNC,
			  LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR |
			  LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH);

    if (!sftp_handle) {
	fprintf(stderr, "Unable to open file with SFTP\n");
	errorno = 9;
	goto shutdown;
    }

    fprintf(stderr, "libssh2_sftp_open() is done, now send data!\n");

    do {
	nread = fread(mem, 1, sizeof(mem), local);
	if (nread <= 0) {
	    /* end of file */
	    break;
	}
	ptr = mem;

	do {
	    /* write data in a loop until we block */
	    rc = libssh2_sftp_write(sftp_handle, ptr, nread);

	    if (rc < 0)
		break;
	    ptr += rc;
	    nread -= rc;
	} while (nread);

    } while (rc > 0);

    libssh2_sftp_close(sftp_handle);

    libssh2_sftp_shutdown(sftp_session);



  shutdown:

    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");

    libssh2_session_free(session);


#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    if (local)
	fclose(local);
    fprintf(stderr, "all done\n");

    libssh2_exit();


    return errorno;
}


/*远程创建目录*/
int sftp_mkdir(struct ssh_struct *conf)
{
    unsigned long hostaddr;
    int sock, i, auth_pw = 1;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    const char *username = conf->user;
    const char *password = conf->pass;
    const char *sftppath = conf->target;
    int rc;
    LIBSSH2_SFTP *sftp_session;
    int errorno = 0;

#ifdef WIN32
    WSADATA wsadata;

    WSAStartup(MAKEWORD(2, 0), &wsadata);
#endif

    hostaddr = inet_addr(conf->host);
    rc = libssh2_init(0);

    if (rc != 0) {
	fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
	return 1;
    }

    /*
     * The application code is responsible for creating the socket
     * and establishing the connection
     */
    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr *) (&sin),
		sizeof(struct sockaddr_in)) != 0) {
	fprintf(stderr, "failed to connect!\n");
	return 2;
    }

    /* Create a session instance
     */
    session = libssh2_session_init();

    if (!session)
	return 3;

    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */
    rc = libssh2_session_handshake(session, sock);

    if (rc) {
	fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
	return 4;
    }

    /* At this point we havn't yet authenticated.  The first thing to do
     * is check the hostkey's fingerprint against our known hosts Your app
     * may have it hard coded, may go to a file, may present it to the
     * user, that's your call
     */
    fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

    fprintf(stderr, "Fingerprint: ");
    for (i = 0; i < 20; i++) {
	fprintf(stderr, "%02X ", (unsigned char) fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if (auth_pw) {
	/* We could authenticate via password */
	if (libssh2_userauth_password(session, username, password)) {

	    fprintf(stderr, "Authentication by password failed.\n");
	    errorno = 5;
	    goto shutdown;
	}
    } else {
	/* Or by public key */
	if (libssh2_userauth_publickey_fromfile(session, username,
						"/home/username/.ssh/id_rsa.pub",
						"/home/username/.ssh/id_rsa",
						password)) {
	    fprintf(stderr, "\tAuthentication by public key failed\n");
	    errorno = 6;
	    goto shutdown;
	}
    }

    sftp_session = libssh2_sftp_init(session);


    if (!sftp_session) {
	fprintf(stderr, "Unable to init SFTP session\n");
	errorno = 7;
	goto shutdown;
    }

    /* Since we have not set non-blocking, tell libssh2 we are blocking */
    libssh2_session_set_blocking(session, 1);


    /* Make a directory via SFTP */
    rc = libssh2_sftp_mkdir(sftp_session, sftppath,
			    LIBSSH2_SFTP_S_IRWXU |
			    LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP
			    | LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH);

    if (rc)
	fprintf(stderr, "libssh2_sftp_mkdir failed: %d\n", rc);

    libssh2_sftp_shutdown(sftp_session);


  shutdown:

    libssh2_session_disconnect(session,
			       "Normal Shutdown, Thank you for playing");

    libssh2_session_free(session);


#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    fprintf(stderr, "all done\n");

    libssh2_exit();


    return errorno;
}
