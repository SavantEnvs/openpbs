/* Attribute value decoders (and the encode/set/compare/free paths over what they accept). */
#include <pbs_config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pbs_ifl.h"
#include "list_link.h"
#include "attribute.h"

struct attr_ops {
	int (*decode)(attribute *, char *, char *, char *);
	int (*encode)(const attribute *, pbs_list_head *, char *, char *, int, svrattrl **);
	int (*set)(attribute *, attribute *, enum batch_op);
	int (*comp)(attribute *, attribute *);
	void (*release)(attribute *);
};

static const struct attr_ops ops[] = {
	{decode_b, encode_b, set_b, comp_b, free_null},
	{decode_c, encode_c, set_c, comp_c, free_null},
	{decode_f, encode_f, set_f, comp_f, free_null},
	{decode_l, encode_l, set_l, comp_l, free_null},
	{decode_ll, encode_ll, set_ll, comp_ll, free_null},
	{decode_size, encode_size, set_size, comp_size, free_null},
	{decode_time, encode_time, set_l, comp_l, free_null},
	{decode_str, encode_str, set_str, comp_str, free_str},
	{decode_arst, encode_arst, set_arst, comp_arst, free_arst},
	{decode_hold, encode_hold, set_l, comp_hold, free_null},
	{decode_unkn, encode_unkn, set_unkn, comp_unkn, free_unkn},
};

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct attr_ops *op;
	attribute a, b;
	pbs_list_head head;
	char *buf;

	if (size < 1)
		return -1;
	op = &ops[data[0] % (sizeof(ops) / sizeof(ops[0]))];
	buf = (char *) malloc(size);
	if (buf == NULL)
		return 0;
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	if (op->decode(&a, "attr", NULL, buf) == 0 && (a.at_flags & ATR_VFLAG_SET)) {
		CLEAR_HEAD(head);
		if (op->encode(&a, &head, "attr", NULL, ATR_ENCODE_CLIENT, NULL) > 0)
			free_attrlist(&head);
		if (op->set != set_unkn) {
			(void) op->set(&b, &a, SET);
			(void) op->comp(&a, &b);
			op->release(&b);
		}
	}
	op->release(&a);
	free(buf);
	return 0;
}
