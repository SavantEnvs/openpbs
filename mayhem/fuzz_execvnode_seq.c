/* exec_vnode sequence condensing/unrolling ("(n1:ncpus=1)+(n1:ncpus=1)" <-> "(n1:ncpus=1)*2"). */
#include <pbs_config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libutil.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf, *copy, *condensed, **unrolled, **tofree = NULL;

	if (size < 1)
		return -1;
	buf = (char *) malloc(size + 1);
	copy = (char *) malloc(size + 1);
	if (buf == NULL || copy == NULL) {
		free(buf);
		free(copy);
		return 0;
	}
	memcpy(buf, data, size);
	buf[size] = '\0';
	memcpy(copy, data, size);
	copy[size] = '\0';

	condensed = condense_execvnode_seq(buf);
	free(condensed);

	(void) get_execvnodes_count(copy);
	unrolled = unroll_execvnode_seq(copy, &tofree);
	if (unrolled != NULL) {
		free_execvnode_seq(tofree);
		free(unrolled);
	}
	free(buf);
	free(copy);
	return 0;
}
