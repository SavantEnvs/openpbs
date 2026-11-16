/* Select / exec_vnode specification parsers: chunks, '+' separated specs, node:resource=value lists, nodes/select attribute decoding. */
#include <pbs_config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pbs_ifl.h"
#include "list_link.h"
#include "attribute.h"
#include "grunt.h"

static void
parse_spec(char *str)
{
	char *last = NULL;
	int hp = 0;
	char *tok = parse_plus_spec_r(str, &last, &hp);

	while (tok != NULL) {
		int nchk = 0, nelem = 0, nkve = 0, dflt = 0;
		struct key_value_pair *kv = NULL;
		char *node = NULL;
		int nl = 0, nlkv = 0;
		struct key_value_pair *kv2 = NULL;
		char *copy = strdup(tok);

		if (copy == NULL)
			return;
		(void) parse_chunk_r(tok, &nchk, &nelem, &nkve, &kv, &dflt);
		free(kv);
		(void) parse_node_resc_r(copy, &node, &nl, &nlkv, &kv2);
		free(kv2);
		free(copy);
		tok = parse_plus_spec_r(last, &last, &hp);
	}
}

static void
decode_and_free(int (*fn)(attribute *, char *, char *, char *), char *name, char *val)
{
	attribute a;

	memset(&a, 0, sizeof(a));
	(void) fn(&a, name, NULL, val);
	free_str(&a);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf;
	uint8_t mode;

	if (size < 1)
		return -1;
	mode = data[0] % 3;
	buf = (char *) malloc(size);
	if (buf == NULL)
		return 0;
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';

	switch (mode) {
		case 0:
			parse_spec(buf);
			break;
		case 1:
			decode_and_free(decode_select, "Resource_List", buf);
			break;
		default:
			decode_and_free(decode_nodes, "Resource_List", buf);
			break;
	}
	free(buf);
	return 0;
}
