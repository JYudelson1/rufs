/*
 *  Copyright (C) 2022 CS416/518 Rutgers CS
 *	RU File System
 *	File:	rufs.c
 *
 */

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#include <limits.h>
#include <pthread.h>

#include "block.h"
#include "rufs.h"

char diskfile_path[PATH_MAX];

// Declare your in-memory data structures here
	// Superblock info should be held in memory
	struct superblock *disk;
	// Various locks for thread safety
	pthread_mutex_t fs_lock;
	// set to 1 for debug messages
	int debug = 0;
	// For tracking used blocks
	int used_blocks = 0;

// Function for inline warnings
int fs_warn(const char* msg, void* buf){
	fprintf(stdout, "%s\n", msg);
	if (buf) free(buf);
	return -1;
}
/*
 * Get available inode number from bitmap
 */
int get_avail_ino() {
	// We use a 2d array of inode_bitmap blocks, bc there is no guarantee
	// that the bitmap fits in one block, i.e. BLOCKSIZE*8 >= MAX_INUM
	unsigned int num_inomap_blks = disk->d_bitmap_blk - disk->i_bitmap_blk;
	unsigned char **inomap = (unsigned char**)malloc(sizeof(unsigned char*) * num_inomap_blks);
	for (int i = 0; i < num_inomap_blks; i++){
		inomap[i] = (unsigned char*)malloc(BLOCK_SIZE);
	}
	int ret;
	long inode_num = -1;
	// Step 1: Read inode bitmap from disk
	for (int i = 0; i < num_inomap_blks; i++){
		ret = bio_read(disk->i_bitmap_blk + i, inomap[i]);
		if (ret < 0) perror("error reading inode bitmap");
	}

	// Step 2: Traverse inode bitmap to find an available slot
	int inomap_blk, inomap_offset;
	for (int i = 0; i < disk->max_inum; i++){
		inomap_blk = i / (BLOCK_SIZE * 8);
		inomap_offset = i - (inomap_blk * BLOCK_SIZE * 8);
		// if (debug) printf("Inode %d is on block %d with offset %d, and has validity %d\n",
		// 	i, inomap_blk, inomap_offset, get_bitmap(inomap[inomap_blk], inomap_offset));
		if (get_bitmap(inomap[inomap_blk], inomap_offset) == 0){
			inode_num = i;
			break;
		}
	}
	// Step 3: Update inode bitmap and write to disk
	// ensure an open inode was found
	if (inode_num == -1){
		printf("No more available inodes!\n");
		return -1;
	}

	// Update inode bitmap and write to disk
	set_bitmap(inomap[inomap_blk], inomap_offset);
	ret = bio_write(disk->i_bitmap_blk + inomap_blk, inomap[inomap_blk]);
	if (ret < 0) perror("error writing inode bitmap");

	for (int i = 0; i < num_inomap_blks; i++){
		free(inomap[i]);
	}
	free(inomap);

	return inode_num;
}
/*
 * Get available data block number from bitmap
 */
int get_avail_blkno() {
	// We use a 2d array of blk_bitmap blocks, bc there is no guarantee
	// that the bitmap fits in one block, i.e. BLOCKSIZE*8 >= MAX_DNUM
	unsigned int num_blkmap_blks = disk->i_start_blk - disk->d_bitmap_blk;
	unsigned char **blkmap = (unsigned char**)malloc(sizeof(unsigned char*) * num_blkmap_blks);
	for (int i = 0; i < num_blkmap_blks; i++){
		blkmap[i] = (unsigned char*)malloc(BLOCK_SIZE);
	}
	int ret;
	long blk_num = -1;
	// Step 1: Read data block bitmap from disk
	for (int i = 0; i < num_blkmap_blks; i++){
		ret = bio_read(disk->d_bitmap_blk + i, blkmap[i]);
		if (ret < 0) perror("error reading data block bitmap");
	}

	// Step 2: Traverse data block bitmap to find an available slot
	int blkmap_blk, blkmap_offset;
	for (int i = 0; i < disk->max_dnum; i++){
		blkmap_blk = i / (BLOCK_SIZE * 8);
		blkmap_offset = i - (blkmap_blk * BLOCK_SIZE * 8);
		// if (debug) printf("blknum %d is on block %d with offset %d, and has validity %d\n",
		// 	i, blkmap_blk, blkmap_offset, get_bitmap(blkmap[blkmap_blk], blkmap_offset));
		if (i >= (MAX_DNUM - disk->d_start_blk)){
			// attempting to search for a block outside of the disk...
			break;
		}
		if (get_bitmap(blkmap[blkmap_blk], blkmap_offset) == 0){
			blk_num = i;
			break;
		}
	}
	// Step 3: Update data block bitmap and write to disk
	// ensure an open data block was found
	if (blk_num == -1){
		printf("No more available data blocks!\n");
		return -1;
	}

	// Update data block bitmap and write to disk
	used_blocks++;
	set_bitmap(blkmap[blkmap_blk], blkmap_offset);
	ret = bio_write(disk->d_bitmap_blk + blkmap_blk, blkmap[blkmap_blk]);
	if (ret < 0) {perror("error writing data block bitmap"); return -1;}

	for (int i = 0; i < num_blkmap_blks; i++){
		free(blkmap[i]);
	}
	free(blkmap);

	return blk_num + disk->d_start_blk;
}
/*
 * Operations for unsetting bits in bitmap
 */
int unset_db_bitmap   (int blkno){
	blkno -= disk->d_start_blk;
	int blk_page = blkno / BLOCK_SIZE;
	int offset = blkno - (BLOCK_SIZE * blk_page);
	bitmap_t buf = malloc(BLOCK_SIZE);

	// read the correct part of the bitmap
	int ret = bio_read(disk->d_bitmap_blk + blk_page, buf);
	if (ret < 0) return ret;
	unset_bitmap(buf, offset); // unset buf at correct loc
	ret = bio_write(disk->d_bitmap_blk + blk_page, buf);
	if (ret < 0) return ret;

	used_blocks--;
	free(buf);
	return 0;
}
int unset_inode_bitmap(int   ino){
	int blk_page = ino / BLOCK_SIZE;
	int offset = ino - (BLOCK_SIZE * blk_page);
	bitmap_t buf = malloc(BLOCK_SIZE);

	// read the correct part of the bitmap
	int ret = bio_read(disk->i_bitmap_blk + blk_page, buf);
	if (ret < 0) return ret;
	unset_bitmap(buf, offset); // unset buf at correct loc
	ret = bio_write(disk->i_bitmap_blk + blk_page, buf);
	if (ret < 0) return ret;

	free(buf);
	return 0;
}
/*
 * inode operations
 */
int readi (uint16_t ino, struct inode *inode) {
	unsigned char *buf = (unsigned char*)malloc(BLOCK_SIZE);
	int ret;
	uint32_t ino_per_blk = (BLOCK_SIZE / sizeof(struct inode));
  // Step 1: Get the inode's on-disk block number
	uint32_t blk_num = disk->i_start_blk + ino / ino_per_blk;
  // Step 2: Get offset of the inode in the inode on-disk block
	uint32_t offset = ino - ((blk_num - disk->i_start_blk) * ino_per_blk);
  // Step 3: Read the block from disk and then copy into inode structure
	ret = bio_read(blk_num, buf);
	if (ret < 0 && debug) perror("error reading an inode");
	unsigned char *ino_start = buf + sizeof(struct inode) * offset;
	memcpy(inode, ino_start, sizeof(struct inode));

	free(buf);
	return 0;
}
int writei(uint16_t ino, struct inode *inode) {
	unsigned char *buf = (unsigned char*)malloc(BLOCK_SIZE);
	int ret;
	uint32_t ino_per_blk = (BLOCK_SIZE / sizeof(struct inode));
	// Step 1: Get the block number where this inode resides on disk
	uint32_t blk_num = disk->i_start_blk + ino / ino_per_blk;
	// Step 2: Get the offset in the block where this inode resides on disk
	uint32_t offset = ino - ((blk_num - disk->i_start_blk) * ino_per_blk);
	// Step 3: Write inode to disk
	ret = bio_read(blk_num, buf);
	if (ret < 0 && debug) perror("error reading an inode");
	unsigned char *ino_start = buf + sizeof(struct inode) * offset;
	memcpy(ino_start, inode, sizeof(struct inode));
	ret = bio_write(blk_num, buf);
	if (ret < 0) perror("error writing an inode");

	free(buf);
	return 0;
}
/*
 * directory operations
 */
int dir_find  (                        uint16_t   ino, const char *fname, size_t name_len, struct dirent *dirent) {
	struct inode i_dir;
	struct dirent dir_tmp;
	int ret;

	if (debug) printf("dir_find: Searching for '%s' in dir(ino=%d)\n", fname, ino);
  // Step 1: Call readi() to get the inode using ino (inode number of current directory)
	ret = readi(ino, &i_dir);
	if (ret < 0) perror("directory in dir_find does not exist");
  // Step 2: Get data block of current directory from inode

	int num_blocks = i_dir.vstat.st_blocks;
	unsigned char **buf = (unsigned char**)malloc(sizeof(unsigned char*) * num_blocks);
	for (int i = 0; i < num_blocks; i++){
		buf[i] = malloc(BLOCK_SIZE);
		// read the dir entries into buf
		ret = bio_read(i_dir.direct_ptr[i], buf[i]);
		if (ret < 0) perror("error reading dir's dirents in dir_add");
	}

  // Step 3: Read directory's data block and check each directory entry.
  //If the name matches, then copy directory entry to dirent structure
	long max_num_entries = BLOCK_SIZE / sizeof(struct dirent);
	long offset, blknum;
	for (int i = 0; i < max_num_entries*num_blocks; i++){
		blknum = i / max_num_entries;
		offset = (i - blknum*max_num_entries) * sizeof(struct dirent);
		memcpy(&dir_tmp, buf[blknum] + offset, sizeof(struct dirent));
		// if (debug) printf("Phantom dirent has ptr=%p, name '%s', ino=%d, and validity=%d\n",
		// 		buf[blknum]+offset, dir_tmp.name, dir_tmp.ino, dir_tmp.valid);
		if (dir_tmp.valid && strcmp(dir_tmp.name, fname) == 0){
			// Correct dirent found
			if (dirent) memcpy(dirent, &dir_tmp, sizeof(struct dirent));
			for (int i = 0; i < num_blocks; i++) {free(buf[i]);}
			free(buf);
			return i;
		}
	}

	for (int i = 0; i < num_blocks; i++) {free(buf[i]);}
	free(buf);
	// No valid dirents found
	return -1;
}
int dir_add   (struct inode dir_inode, uint16_t f_ino, const char *fname, size_t name_len) {

	int ret, found;
	long offset, blknum;
	struct dirent new, dir_tmp;
	long max_num_entries = BLOCK_SIZE / sizeof(struct dirent);
	int num_blocks = dir_inode.vstat.st_blocks;

	if (debug) printf("dir_add: Adding file(ino=%d, name=%s) to dir(ino=%d)\n",
			f_ino, fname, dir_inode.ino);
	// Step 1: Read dir_inode's data block and check each directory entry of dir_inode
	// Step 2: Check if fname (directory name) is already used in other entries
	// Note: we can outsource this to dir_find
	ret = dir_find(dir_inode.ino, fname, name_len, NULL);
	if (ret >= 0) return -1; // file already exists

	// Step 3: Add directory entry in dir_inode's data block and write to disk
	unsigned char **buf = (unsigned char**)malloc(sizeof(unsigned char*) * (num_blocks+1));
	for (int i = 0; i < num_blocks; i++){
		buf[i] = malloc(BLOCK_SIZE);
		// read the dir entries into buf
		ret = bio_read(dir_inode.direct_ptr[i], buf[i]);
		if (ret < 0) perror("error reading dir's dirents in dir_add");
	}
	// make new dirent
	new.valid = 1;
	new.ino = f_ino;
	strcpy(new.name, fname);
	new.len = name_len;
	// find space for dirent in the data block
	found = 0;
	for (int i = 0; i < max_num_entries*num_blocks; i++){
		// search through buf for invalid dirents
		blknum = i / max_num_entries;
		offset = (i - blknum*max_num_entries) * sizeof(struct dirent);
		memcpy(&dir_tmp, buf[blknum] + offset, sizeof(struct dirent));
		//printf("Phantom dirent %d has validity %d\n", i, dir_tmp.valid);
		if (dir_tmp.valid != 1){ // found an invalid node
			// store new dirent in buf
			found = 1;
			memcpy(buf[blknum] + offset, &new, sizeof(struct dirent));
			break;
		}
	}
	if (!found){
		if (dir_inode.direct_ptr[15] > 0){ // Directory uses all data blocks
			fprintf(stderr, "Dir is full, cannot add %s\n", fname);
			return -1;
		}
		// Allocate new data block
		if (debug) printf("Adding data block #%d to dir(ino=%d)\n", num_blocks+1, dir_inode.ino);
		blknum = num_blocks;
		dir_inode.vstat.st_blocks++;
		dir_inode.direct_ptr[blknum] = get_avail_blkno();
		buf[blknum] = malloc(BLOCK_SIZE);
		memcpy(buf[blknum], &new, sizeof(struct dirent));
		if (debug) printf("Dir(ino=%d) now has %ld blocks, last at %d\n", dir_inode.ino, dir_inode.vstat.st_blocks, dir_inode.direct_ptr[blknum]);
	}

	// Update directory inode
	dir_inode.size 					+= sizeof(struct dirent); // increase size
	dir_inode.vstat.st_size += sizeof(struct dirent);
	time(&dir_inode.vstat.st_mtime); 				 // change last modification time
	writei(dir_inode.ino, &dir_inode); 			 // save changes

	// Write directory entry
	// 	Note: if an invalid dirent was found, the new dirent
	//				has already been copied to buf
	ret = bio_write(dir_inode.direct_ptr[blknum], buf[blknum]);
	if (ret < 0) perror("error writing dir's dirents in dir_add");

	// Freeing
	for (int i = 0; i <= num_blocks; i++){
		if (buf[i]) free(buf[i]);
	}
	free(buf);

	return 0;
}
int dir_remove(struct inode dir_inode,                 const char *fname, size_t name_len) {
	// Step 1: Read dir_inode's data block and checks each directory entry of dir_inode
	// Step 2: Check if fname exist
	if (debug) printf("dir_remove: removing file(name=%s) from dir(ino=%d)\n", fname, dir_inode.ino);
	struct dirent dir_tmp;
	int dirent_num = dir_find(dir_inode.ino, fname, name_len, &dir_tmp);
	if (dirent_num < 0){
		fprintf(stderr, "%s not found, cannot be removed\n", fname);
		return -1;
	}
	// Step 3: If exist, then remove it from dir_inode's data block and write to disk
	char *buf = malloc(BLOCK_SIZE);
	int ret = bio_read(dir_inode.direct_ptr[0], buf);
	if (ret < 0) return fs_warn("Cannot read from dir in dir_remove", buf);

	dir_tmp.valid = 0; // Invalidate dirent
	//Copy invalidated dirent into buf at the right place
	memcpy(buf + (dirent_num * sizeof(struct dirent)), &dir_tmp, sizeof(struct dirent));
	// Use buf to overwrite the data block in memory
	ret = bio_write(dir_inode.direct_ptr[0], buf);
	if (ret < 0) return fs_warn("Cannot invalidate dirent in dir_remove", buf);

	// Update dir_inode
	dir_inode.size -= sizeof(struct dirent);
	dir_inode.vstat.st_size = dir_inode.size;
	time(&dir_inode.vstat.st_mtime);
	writei(dir_inode.ino, &dir_inode);

	free(buf);
	return 0;
}
/*
 * namei operation
 */
int get_node_by_path(const char *path, uint16_t ino, struct inode *inode) {
	// Step 1: Resolve the path name, walk through path, and finally, find its inode.
	// Note: You could either implement it in a iterative way or recursive way
	// I will be implementing this iteratively
	int ret;
	struct dirent dir_tmp;
	if (debug) printf("Getting node of %s\n", path);
	// Make a copy of the path name so we can use strtok on it
	char pathcpy1[PATH_MAX], pathcpy2[PATH_MAX];
	strcpy(pathcpy1, path);
	strcpy(pathcpy2, path);
	char *base_name = basename(pathcpy1);
	char *path_name = dirname(pathcpy2);

	// If in root return 0
	if (strcmp(path, "/")==0){
		readi(0, inode);
		return 0;
	}

	char * token = strtok(path_name, "/");

	// While there are more parts of the path to process
	while (token != NULL){
		if (debug) printf("The token is %s, remaining path is %s\n", token, path_name);
		// ino represents current dir
		// token represents the name of the next file / subdirectory
		// So we find the dirent corresponding to that name:
		ret = dir_find(ino, token, strlen(token), &dir_tmp);
		if (ret < 0) {
			if (debug) perror("error searching for inode");
			return ret;
		}
		// Now looking in the sub_directory's ino for the next token
		// or, if dir_tmp points to the final dest, will end (when token==NULL)
		ino = dir_tmp.ino;
		token = strtok(NULL, "/");
	}

	// In final directory
	ret = dir_find(ino, base_name, strlen(base_name), &dir_tmp);
	if (ret < 0) {
		if (debug) perror("error searching for inode");
		return ret;
	}

	// read the inode info of the final destination to *inode
	ret = readi(dir_tmp.ino, inode);

	return ret;
}
/*
 * Make file system
 */
int rufs_mkfs() {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_mkfs\n");
	int ret; //for debugging

	// write superblock information
	if (!disk) disk = (struct superblock*)malloc(sizeof(struct superblock));
	disk->magic_num = MAGIC_NUM;
	disk->max_inum  = MAX_INUM;
	disk->max_dnum  = MAX_DNUM;
	// Disk is partitioned into 5 segments:
	//		 	1. Superblock info (size = 1 block)
	//			2. Inode bitmap 	 (size = ceil(MAX_INUM / (BLOCK_SIZE*8)) blocks)
	//					Because one block holds (BLOCK_SIZE*8) bits
	//			3. data bitmap 		 (size = ceil(MAX_DNUM / (BLOCK_SIZE*8)) blocks)
	//			4. inode blocks    (size = ceil(MAX_INUM * sizeof(struct inode) / BLOCK_SIZE) blocks)
	//					Because each block holds (BLOCK_SIZE / sizeof(struct inode) inodes)
	//			5. data blocks     (size = everything left over)
	// We use this information to inform the rest of superblock info
	disk->i_bitmap_blk = 1;
	disk->d_bitmap_blk = 1 + (MAX_INUM / (BLOCK_SIZE*8));
	if (MAX_INUM % (BLOCK_SIZE*8) != 0) disk->d_bitmap_blk++;
	disk->i_start_blk = disk->d_bitmap_blk + (MAX_DNUM / (BLOCK_SIZE*8));
	if (MAX_DNUM % (BLOCK_SIZE*8) != 0) disk->i_start_blk++;
	disk->d_start_blk = disk->i_start_blk + ((MAX_INUM * sizeof(struct inode)) / BLOCK_SIZE);
	if ((MAX_INUM * sizeof(struct inode)) % (BLOCK_SIZE) != 0) disk->d_start_blk++;
	unsigned char *buf = (unsigned char*)calloc(BLOCK_SIZE, sizeof(char));
	memcpy(buf, disk, sizeof(struct superblock));
	bio_write(0, buf);
	free(buf);
	//initialize inode

	bitmap_t zero_map = calloc(BLOCK_SIZE, sizeof(char));
	for (int i = disk->i_bitmap_blk; i < disk->d_bitmap_blk; i++){
		// For every block in the inode bitmap
		ret = bio_write(i, zero_map);
		if (ret < 0) perror("error writing inode bitmap in rufs_mkfs");
	}
	//initialize data block bitmap
	for (int i = disk->d_bitmap_blk; i < disk->i_start_blk; i++){
		// For every block in the data block bitmap
		ret = bio_write(i, zero_map);
		if (ret < 0) perror("error writing inode bitmap in rufs_mkfs");
	}

	//update inode for root directory
	//Note: this auto-updates inode/data bitmaps, in get_avail_ino & get_avail_blkno
	// Basic inode info
	struct inode i_dir;
	i_dir.ino = get_avail_ino(); // zero
	i_dir.valid = 1;
	i_dir.size = 0;
	i_dir.type = S_IFDIR | 0755;
	i_dir.link = 2;
	// inode vstat info
	i_dir.vstat.st_ino = i_dir.ino;
	i_dir.vstat.st_mode = S_IFDIR | 0755;
	i_dir.vstat.st_nlink = 2;
	i_dir.vstat.st_uid = getuid();
	i_dir.vstat.st_gid = getgid();
	i_dir.vstat.st_size = sizeof(struct dirent);
	time(&i_dir.vstat.st_atime);
	time(&i_dir.vstat.st_mtime);
	i_dir.vstat.st_blksize = BLOCK_SIZE;
	i_dir.vstat.st_blocks = 1;
	// initialize one data block
	int blkno = get_avail_blkno();
	if (blkno < 0) perror("Error allocing block for root!");

	//Init empty directory space
	i_dir.direct_ptr[0] = blkno;
	struct dirent zero_dir;
	zero_dir.valid = 0;
	zero_dir.ino = MAX_INUM + 1;
	for (int i = 0; i < (BLOCK_SIZE/sizeof(struct dirent)); i++){
		memcpy(zero_map+(i*sizeof(struct dirent)), &zero_dir, sizeof(struct dirent));
	}
	bio_write(blkno, zero_map);
	// Step 6: Call writei() to write inode to disk
	writei(i_dir.ino, &i_dir);
	// Write the "."/self-referential dirent to the data block
	dir_add(i_dir, i_dir.ino, ".", strlen("."));

	free(zero_map);
	pthread_mutex_unlock(&fs_lock);
	return 0;
}
/*
 * FUSE file operations
 */
static void *rufs_init(struct fuse_conn_info *conn) {
	if (debug) printf("Entering rufs_init\n");
	// Step 1a: If disk file is not found, call mkfs
	// NB: Not sure if this is right
	if (dev_open(diskfile_path) == -1){
			// Call dev_init() to initialize (Create) Diskfile
			dev_init(diskfile_path);
			rufs_mkfs();
			return NULL;
	}
  // Step 1b: If disk file is found, just initialize in-memory data structures
  // and read superblock from disk

	unsigned char buf[BLOCK_SIZE];
	disk = (struct superblock*)malloc(sizeof(struct superblock));

	int ret = bio_read(0, buf);
	if (ret < 0) fprintf(stdout, "Can't read disk info\n");
	memcpy(disk, buf, sizeof(struct superblock));

	if (disk->max_inum == 0) rufs_mkfs();

	return NULL;
}
static void rufs_destroy(void *userdata) {
	if (debug) printf("Entering rufs_destroy\n");
	// Step 1: De-allocate in-memory data structures
	printf("\nTotal blocks used:\nFor superblock: %ud\nFor bitmaps: %ud\nFor inodes: %ud\nFor data blocks: %d\n",
						disk->i_bitmap_blk, disk->i_start_blk-disk->i_bitmap_blk, disk->d_start_blk-disk->i_start_blk, used_blocks);
	free(disk);
	pthread_mutex_unlock(&fs_lock);

	// Step 2: Close diskfile
	dev_close();

}

static int rufs_getattr(const char *path, struct stat *stbuf) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_getattr for %s\n", path);
	// Step 1: call get_node_by_path() to get inode from path
	struct inode inode_f;
	int ret = get_node_by_path(path, 0, &inode_f);

	if (ret < 0) { // File doesn't exist
		if (debug) printf("In get_attr: %s doesn't exist\n", path);
		pthread_mutex_unlock(&fs_lock);
		return -2;
	}

	// Step 2: fill attribute of file into stbuf from inode
	stbuf->st_ino     = inode_f.vstat.st_ino;
	stbuf->st_mode    = inode_f.vstat.st_mode;
	stbuf->st_nlink   = inode_f.vstat.st_nlink;
	stbuf->st_uid     = inode_f.vstat.st_uid;
	stbuf->st_gid     = inode_f.vstat.st_gid;
	stbuf->st_size    = inode_f.vstat.st_size;
	stbuf->st_blksize = inode_f.vstat.st_blksize;
	stbuf->st_blocks  = inode_f.vstat.st_blocks;
	stbuf->st_atime   = inode_f.vstat.st_atime;
	stbuf->st_mtime   = inode_f.vstat.st_mtime;

	if (debug) printf("stbuf has ino %ld, size %ld, isdir? %d isreg? %d\n", stbuf->st_ino, stbuf->st_size, S_ISDIR(stbuf->st_mode), S_ISREG(stbuf->st_mode));

	pthread_mutex_unlock(&fs_lock);
	return 0;
}
static int rufs_opendir(const char *path, struct fuse_file_info *fi) {
	//NB: THIS IS ALMOST DEF WRONG
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_opendir\n");
	// Step 1: Call get_node_by_path() to get inode from path
	// Note: this will only search from root
	struct inode i_dir;
	int ino = get_node_by_path(path, 0, &i_dir);
	if (ino < 0) return fs_warn("Can't find file dir in opendir", NULL);

	// Ensure file is a dir
	if (!S_ISDIR(i_dir.type)){
		printf("Cannot opendir %s: not a directory!\n", path);
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}

	// update a_time
	readi(ino, &i_dir);
	time(&i_dir.vstat.st_atime);
	writei(ino, &i_dir);

	pthread_mutex_unlock(&fs_lock);
  return 0;
}
static int rufs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_readdir\n");
	// Step 1: Call get_node_by_path() to get inode from path
	struct inode inode_d;
	int ret = get_node_by_path(path, 0, &inode_d);
	if (ret < 0) return fs_warn("Erroring in readdir", NULL);

	// Ensure file is a dir
	if (!S_ISDIR(inode_d.type)){
		printf("Cannot readdir %s: not a directory!\n", path);
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}

	// Step 2: Read directory entries from its data blocks, and copy them to filler
	struct dirent dir_tmp; // For iterating through all dirents of current dir
	struct inode inode_f; // For getting the inode / stats of each file
	int dir_offset, blknum;
	int num_per_block = BLOCK_SIZE / (sizeof(struct dirent));

	// read the dir entries into buf
	int num_blocks = inode_d.vstat.st_blocks;
	unsigned char **buf = (unsigned char **)malloc(num_blocks * sizeof(unsigned char*));
	for (int i=0; i < num_blocks; i++){
		buf[i] = malloc(BLOCK_SIZE);
		ret = bio_read(inode_d.direct_ptr[i], buf[i]);
		if (ret < 0) perror("error reading dir's dirents in readdir");
	}

	for (long i = 2; i < num_blocks * num_per_block; i++){
		// Skip "." and ".."
		// search through buf for valid dirents
		blknum = i / num_per_block;
		dir_offset = (i - blknum * num_per_block) * sizeof(struct dirent);
		memcpy(&dir_tmp, buf[blknum] + dir_offset, sizeof(struct dirent));
		if (dir_tmp.valid==1){ // found a valid node
			// Grab file's stats via dir_tmp->inode
			ret = readi(dir_tmp.ino, &inode_f);
			if (ret < 0) return fs_warn("Erroring in readdir", buf);

			// use filler to place info into buffer
			filler(buffer, dir_tmp.name, &inode_f.vstat, i);
		}
	}

	//Freeing
	for (int i = 0; i < num_blocks; i++){
		free(buf[i]);
	}
	free(buf);
	pthread_mutex_unlock(&fs_lock);
	return 0;
}

static int rufs_mkdir(const char *path, mode_t mode) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_mkdir\n");
	char *dir_p, *base_p, pathcpy1[PATH_MAX], pathcpy2[PATH_MAX];
	struct inode i_dir;
	// Step 1: Use dirname() and basename() to separate parent directory path and target directory name
	strcpy(pathcpy1, path);
	strcpy(pathcpy2, path);
	dir_p  = dirname((char*)pathcpy1);
	base_p = basename((char*)pathcpy2);
	// Step 2: Call get_node_by_path() to get inode of parent directory
	struct inode parent_dir_inode;
	get_node_by_path(dir_p, 0, &parent_dir_inode);
	// Step 3: Call get_avail_ino() to get an available inode number
	int ino = get_avail_ino();
	if (ino < 0) return fs_warn("No available inodes for mkdir", NULL);

	// Step 4: Call dir_add() to add directory entry of target directory to parent directory
	int ret = dir_add(parent_dir_inode, ino, base_p, strlen(base_p));
	if (ret < 0) return fs_warn("Error adding dirent in mkdir", NULL);

	// Step 5: Update inode for target directory
	// Basic inode info
	i_dir.ino = ino;
	i_dir.valid = 1;
	i_dir.size = 0;
	i_dir.type = S_IFDIR | mode;
	i_dir.link = 2;
	// inode vstat info
	i_dir.vstat.st_ino = ino;
	i_dir.vstat.st_mode = S_IFDIR | mode;
	i_dir.vstat.st_nlink = 2;
	i_dir.vstat.st_uid = getuid();
	i_dir.vstat.st_gid = getgid();
	i_dir.vstat.st_size = sizeof(struct dirent);
	time(&i_dir.vstat.st_atime);
	time(&i_dir.vstat.st_mtime);
	i_dir.vstat.st_blksize = BLOCK_SIZE;
	i_dir.vstat.st_blocks = 1;
	// initialize one data block
	int blkno = get_avail_blkno();
	if (blkno < 0) return fs_warn("No blocks avail for mkdir", NULL);

	i_dir.direct_ptr[0] = blkno;
	for (int i = 1; i < 16; i++){
		i_dir.direct_ptr[i] = -1;
	}
	unsigned char *zero_buf = calloc(BLOCK_SIZE, sizeof(char));
	struct dirent zero_dir;
	zero_dir.valid = 0;
	zero_dir.ino = MAX_INUM + 1;;
	for (int i = 0; i < (BLOCK_SIZE/sizeof(struct dirent)); i++){
		memcpy(zero_buf+(i*sizeof(struct dirent)), &zero_dir, sizeof(struct dirent));
	}
	bio_write(blkno, zero_buf);
	free(zero_buf);
	// Step 6: Call writei() to write inode to disk
	writei(ino, &i_dir);
	// Write the "."/self-referential dirent to the data block
	dir_add(i_dir, ino, ".", strlen("."));
	// Write "..", the parent reference
	dir_add(i_dir, parent_dir_inode.ino, "..", strlen("."));
	//Update the parent's inode
	//Note that the parent inode may have changed
	readi(parent_dir_inode.ino, &parent_dir_inode);
	parent_dir_inode.link++;
	parent_dir_inode.vstat.st_nlink++;
	writei(parent_dir_inode.ino, &parent_dir_inode);

	pthread_mutex_unlock(&fs_lock);
	return 0;
}
static int rufs_rmdir(const char *path) {
	// Needed vars
	if (debug) printf("Entering rufs_rmdir\n");
	int ret;
	char *dir_p, *base_p, pathcpy1[PATH_MAX], pathcpy2[PATH_MAX];
	struct inode i_target, i_parent;

	pthread_mutex_lock(&fs_lock);
	// Step 1: Use dirname() and basename() to separate parent directory path and target directory name
	strcpy(pathcpy1, path);
	strcpy(pathcpy2, path);
	dir_p  = dirname((char*)pathcpy1);
	base_p = basename((char*)pathcpy2);
	// Error handling: Cannot delete root
	if (strcmp(dir_p, "/") == 0 && strcmp(base_p, "/") == 0){
		fprintf(stderr, "Cannot delete root!!");
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}
	// Step 2: Call get_node_by_path() to get inode of target directory
	ret = get_node_by_path(path, 0, &i_target);
	if (ret < 0) return fs_warn("Erroring in rufs_rmdir", NULL);

	// Ensure file is a dir
	if (!S_ISDIR(i_target.type)){
		printf("Cannot rmdir %s: not a directory!\n", path);
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}

	// Error handling: dir must be empty
	if (i_target.size > (2 * sizeof(struct dirent)))
		// Note: empty dir still has "." and ".."
		return fs_warn("Dir must be empty to remove!", NULL);

	// Step 3: Clear data block + bitmap of target directory
	// Clear "." and ".." from data block
	char *buf = calloc(BLOCK_SIZE, sizeof(char));
	ret = bio_write(i_target.direct_ptr[0], buf);
	if (ret < 0) return fs_warn("Cannot clear targets data block in rmdir", buf);
	free(buf);
	// Clear data block in global bitmap
	for (int i = 0; i < 16; i++){
		if (i_target.direct_ptr[i] > 0)
			unset_db_bitmap(i_target.direct_ptr[i]);
	}
	// Clear inode in global bitmap
	unset_inode_bitmap(i_target.ino);
	// Step 5: Call get_node_by_path() to get inode of parent directory
	ret = get_node_by_path(dir_p, 0, &i_parent);
	if (ret < 0) return fs_warn("Erroring in rufs_rmdir", NULL);

	// Step 6: Call dir_remove() to remove directory entry of target directory in its parent directory
	ret = dir_remove(i_parent, base_p, strlen(base_p));
	if (ret < 0) return fs_warn("Cannot remove target from parent in rmdir", NULL);

	// Update parent directory with one fewer link
	readi(i_parent.ino, &i_parent);
	i_parent.link--;
	i_parent.vstat.st_nlink--;
	writei(i_parent.ino, &i_parent);

	pthread_mutex_unlock(&fs_lock);
	return 0;
}

static int rufs_create(const char *path, mode_t mode,                                   struct fuse_file_info *fi) {
	// Needed vars
	int ret, ino;
	char *dir_p, *base_p, path_cpy[PATH_MAX], path_cpy2[PATH_MAX];
	struct inode i_target, i_parent;

	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_create for %s\n", path);
	// Step 1: Use dirname() and basename() to separate parent directory path and target file name
	strcpy(path_cpy2, path);
	dir_p  = dirname((char*)path_cpy2);

	strcpy(path_cpy, path);
	base_p = basename((char*)path_cpy);

	// Step 2: Call get_node_by_path() to get inode of parent directory
	ret = get_node_by_path(dir_p, 0, &i_parent);
	if (ret < 0) return fs_warn("Cannot get parent inode in rufs_create", NULL);
	// Step 3: Call get_avail_ino() to get an available inode number
	ino = get_avail_ino();
	if (ino < 0) return fs_warn("No available inodes for rufs_create", NULL);
	// Step 4: Call dir_add() to add directory entry of target file to parent directory
	ret = dir_add(i_parent, ino, base_p, strlen(base_p));
	if (ret < 0) return fs_warn("Cannot add dirent in rufs_create", NULL);
	// Step 5: Update inode for target file
	// Basic inode info
	i_target.ino = ino;
	i_target.valid = 1;
	i_target.size = 0;
	i_target.type = S_IFREG | mode;
	i_target.link = 1;
	// inode vstat info
	i_target.vstat.st_ino = ino;
	i_target.vstat.st_mode = S_IFREG | mode;
	i_target.vstat.st_nlink = 1;
	i_target.vstat.st_uid = getuid();
	i_target.vstat.st_gid = getgid();
	i_target.vstat.st_size = 0;
	time(&i_target.vstat.st_atime);
	time(&i_target.vstat.st_mtime);
	i_target.vstat.st_blksize = BLOCK_SIZE;
	i_target.vstat.st_blocks = 0;
	// initialize empty data blocks
	for (int i = 0; i < 16; i++){
		i_target.direct_ptr[i] = -1;
	}

	// i_target.direct_ptr[0] = get_avail_blkno();

	// Step 6: Call writei() to write inode to disk
	ret = writei(ino, &i_target);
	if (ret < 0) perror("Error writing new inode in rufs_create");

	if (debug) printf("Succesfully created file at %s w/ ino %d\n", path, ino);
	pthread_mutex_unlock(&fs_lock);
	return 0;
}
static int rufs_open  (const char *path,                                                struct fuse_file_info *fi) {
	//NB: THIS IS ALMOST DEF WRONG
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_open\n");
	struct inode f_inode;
	// Step 1: Call get_node_by_path() to get inode from path
	int ret = get_node_by_path(path, 0, &f_inode);
	// Step 2: If not find, return -1
	if (ret < 0) return fs_warn("Cannot get node by path in rufs_read", NULL);

	// Remember to update a_time
	readi(f_inode.ino, &f_inode);
	time(&f_inode.vstat.st_atime);
	ret = writei(f_inode.ino, &f_inode);
	if (ret < 0) perror("Issue modifying st_atime during open");

	pthread_mutex_unlock(&fs_lock);
	return 0;
}
static int rufs_read  (const char *path,       char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_read\n");
	struct inode f_inode;
	int ret, start_blk, end_blk, fst_blk_start, lst_block_end;
	int start, end;
	int total_bytes, data_ptr, read_bytes;
	unsigned char *tmp_buf = (unsigned char*)malloc(BLOCK_SIZE);
	// Step 1: You could call get_node_by_path() to get inode from path
	ret = get_node_by_path(path, 0, &f_inode);
	if (ret < 0) return fs_warn("Cannot get node by path in rufs_read", tmp_buf);

	// Ensure file is a file
	if (!S_ISREG(f_inode.type)){
		printf("Cannot write to %s: not a file!\n", path);
		free(tmp_buf);
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}

	// Step 2: Based on size and offset, read its data blocks from disk
	start_blk =  offset             / BLOCK_SIZE;
	end_blk   = (offset + size - 1) / BLOCK_SIZE;
	fst_blk_start = offset - (start_blk * BLOCK_SIZE);
	lst_block_end = offset + size - (end_blk * BLOCK_SIZE);

	// Step 3: copy the correct amount of data from offset to buffer
	total_bytes = 0;
	for (int i = start_blk; i <= end_blk; i++){
		// Go through each data block that stores the data
		data_ptr = f_inode.direct_ptr[i];
		// read whole block, unless first or last block
		start = 0;
		end = BLOCK_SIZE;
		if (i == start_blk) start = fst_blk_start;
		if (i == end_blk)   end   = lst_block_end;
		read_bytes = end - start;
		ret = bio_read(data_ptr, tmp_buf);
		if (ret < 0) {
			perror("Error reading data block in rufs_read");
			free(tmp_buf);
			pthread_mutex_unlock(&fs_lock);
			return total_bytes;
		}
		// Copy correct part of tmp_buf into buffer
		memcpy(buffer + total_bytes, tmp_buf + start, read_bytes);
		total_bytes += read_bytes;
	}

	// Note: this function should return the amount of bytes you copied to buffer
	// updates a_time
	time(&f_inode.vstat.st_atime);
	ret = writei(f_inode.ino, &f_inode);
	if (ret < 0) perror("Issue modifying st_atime during read");

	free(tmp_buf);
	pthread_mutex_unlock(&fs_lock);
	return total_bytes;
}
static int rufs_write (const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_write\n");
	struct inode f_inode;
	int ret, start_blk, end_blk, fst_blk_start, lst_block_end;
	int start, end;
	int total_bytes, data_ptr, read_bytes;
	unsigned char *tmp_buf = (unsigned char*)malloc(BLOCK_SIZE);
	// Step 1: You could call get_node_by_path() to get inode from path
	ret = get_node_by_path(path, 0, &f_inode);
	if (ret < 0) return fs_warn("Cannot get node by path in rufs_write", tmp_buf);

	// Ensure file is a file
	if (!S_ISREG(f_inode.type)){
		printf("Cannot write to %s: not a file!\n", path);
		free(tmp_buf);
		pthread_mutex_unlock(&fs_lock);
		return -1;
	}

	// Step 2: Based on size and offset, read its data blocks from disk
	start_blk =  offset             / BLOCK_SIZE;
	end_blk   = (offset + size - 1) / BLOCK_SIZE;
	fst_blk_start = offset - (start_blk * BLOCK_SIZE);
	lst_block_end = offset + size - (end_blk * BLOCK_SIZE);

	// Step 3: Write the correct amount of data from offset to disk
	total_bytes = 0;
	for (int i = start_blk; i <= end_blk; i++){
		// Go through each data block that stores the data
		data_ptr = f_inode.direct_ptr[i];
		// If the needed data_ptr is not allocated
		if (data_ptr <= 0) {
			data_ptr = get_avail_blkno();
			if (data_ptr < 0) perror("Not enough space in rufs_write");
			// update inode
			f_inode.direct_ptr[i] = data_ptr;
			f_inode.vstat.st_blocks += 1;
			// f_inode.size += BLOCK_SIZE;
			// f_inode.vstat.st_size += BLOCK_SIZE;
			writei(f_inode.ino, &f_inode);
		}


		// read whole block, unless first or last block
		start = 0;
		end = BLOCK_SIZE;
		if (i == start_blk) start = fst_blk_start;
		if (i == end_blk)   end   = lst_block_end;
		read_bytes = end - start;
		ret = bio_read(data_ptr, tmp_buf);
		if (ret < 0) {
			perror("Error reading data block in rufs_write");
			free(tmp_buf);
			writei(f_inode.ino, &f_inode);
			pthread_mutex_unlock(&fs_lock);
			return total_bytes;
		}
		// Copy correct part of buffer into tmp_buf
		memcpy(tmp_buf + start, (char*)buffer + total_bytes, read_bytes);
		total_bytes += read_bytes;
		// Write the changed block back
		ret = bio_write(data_ptr, tmp_buf);
		if (ret < 0) {
			perror("Error writing changed data block in rufs_write");
			free(tmp_buf);
			pthread_mutex_unlock(&fs_lock);
			return total_bytes;
		}
		f_inode.size += read_bytes;
		f_inode.vstat.st_size += read_bytes;
	}

	// Step 4: Update the inode info and write it to disk (st_mtime, st_atime, size)
	time(&f_inode.vstat.st_atime);
	time(&f_inode.vstat.st_mtime);
	ret = writei(f_inode.ino, &f_inode);
	if (ret < 0) perror("Issue modifying inode info during write");

	// Note: this function should return the amount of bytes you write to disk
	free(tmp_buf);
	if (debug) printf("Wrote a total of %d bytes\n", total_bytes);
	pthread_mutex_unlock(&fs_lock);
	return total_bytes;
}
static int rufs_unlink(const char *path) {
	pthread_mutex_lock(&fs_lock);
	if (debug) printf("Entering rufs_unlink\n");
	struct inode i_file, i_dir;
	int data_ptr, ret;
	char *base_path, *dir_path, pathcpy1[PATH_MAX], pathcpy2[PATH_MAX];
	unsigned char *buf = (unsigned char*)malloc(BLOCK_SIZE);
	strcpy(pathcpy1, path);
	strcpy(pathcpy2, path);
	// Step 1: Use dirname() and basename() to separate parent directory path and target file name
	dir_path  = dirname((char*)pathcpy1);
	base_path = basename((char*)pathcpy2);
	// Step 2: Call get_node_by_path() to get inode of target file
	ret = get_node_by_path(path, 0, &i_file);
	if (ret < 0) return fs_warn("Erroring in rufs_unlink (cannot fine file inode)", buf);
	// Step 3: Clear data block bitmap of target file
	for (int i = 0; i < 16; i++){
		data_ptr = i_file.direct_ptr[i];
		if (data_ptr > 0) unset_db_bitmap(data_ptr);
	}
	// Step 4: Clear inode bitmap & inode
	i_file.valid = 0;
	writei(i_file.ino, &i_file);
	unset_inode_bitmap(i_file.ino);
	// Step 5: Call get_node_by_path() to get inode of parent directory
	ret = get_node_by_path(dir_path, 0, &i_dir);
	if (ret < 0) return fs_warn("Erroring in rufs_unlink (cannot find dir inode)", buf);
	// Step 6: Call dir_remove() to remove directory entry of target file in its parent directory
	ret = dir_remove(i_dir, base_path, strlen(base_path));
	if (ret < 0) return fs_warn("Erroring in rufs_unlink (remove file's dirent)", buf);

	free(buf);
	pthread_mutex_unlock(&fs_lock);
	return 0;
}

/* Unused functions */
static int rufs_truncate  (const char *path, off_t size) {
	// For this project, you don't need to fill this function
	// But DO NOT DELETE IT!
    return 0;
}
static int rufs_releasedir(const char *path, struct fuse_file_info *fi) {
	// For this project, you don't need to fill this function
	// But DO NOT DELETE IT!
    return 0;
}
static int rufs_release   (const char *path, struct fuse_file_info *fi) {
	// For this project, you don't need to fill this function
	// But DO NOT DELETE IT!
	return 0;
}
static int rufs_flush     (const char *path, struct fuse_file_info *fi) {
	// For this project, you don't need to fill this function
	// But DO NOT DELETE IT!
    return 0;
}
static int rufs_utimens   (const char *path, const struct timespec tv[2]) {
	// For this project, you don't need to fill this function
	// But DO NOT DELETE IT!
    return 0;
}

static struct fuse_operations rufs_ope = {
	.init		    = rufs_init,
	.destroy	  = rufs_destroy,

	.getattr	  = rufs_getattr,
	.readdir	  = rufs_readdir,
	.opendir	  = rufs_opendir,
	.releasedir	= rufs_releasedir,
	.mkdir		  = rufs_mkdir,
	.rmdir		  = rufs_rmdir,

	.create 		= rufs_create,
	.open	 	    = rufs_open,
	.read   		= rufs_read,
	.write 		  = rufs_write,
	.unlink	  	= rufs_unlink,

	.truncate   = rufs_truncate,
	.flush      = rufs_flush,
	.utimens    = rufs_utimens,
	.release	  = rufs_release
};

int main(int argc, char *argv[]) {
	int fuse_stat;

	getcwd(diskfile_path, PATH_MAX);
	strcat(diskfile_path, "/DISKFILE");

	fuse_stat = fuse_main(argc, argv, &rufs_ope, NULL);

	return fuse_stat;
}
