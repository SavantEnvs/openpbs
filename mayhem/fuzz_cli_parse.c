/* Client-side argument parsers used by the qsub/qstat/qselect family: job ids, destinations, user@host lists, stage lists, ranges, name=value pairs. */
#include <pbs_config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pbs_ifl.h"
#include "pbs_internal.h"
#include "cmds.h"
#include "attribute.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf;
	uint8_t mode;

	if (size < 1)
		return -1;
	mode = data[0] % 8;
	buf = (char *) malloc(size);
	if (buf == NULL)
		return 0;
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';

	switch (mode) {
		case 0: {
			char *seq = NULL, *parent = NULL, *cur = NULL;
			if (parse_jobid(buf, &seq, &parent, &cur) == 0) {
				free(seq);
				free(parent);
				free(cur);
			}
			break;
		}
		case 1: {
			char *q = NULL, *s = NULL;
			if (parse_destination_id(buf, &q, &s) == 0) {
				free(q);
				free(s);
			}
			break;
		}
		case 2: {
			char name[MAXPATHLEN + 1], host[PBS_MAXSERVERNAME + 1];
			(void) parse_at_item(buf, name, host);
			break;
		}
		case 3:
			(void) parse_at_list(buf, 0, 0);
			(void) parse_at_list(buf, 1, 0);
			break;
		case 4:
			(void) parse_stage_list(buf);
			break;
		case 5:
			(void) chk_Jrange(buf);
			break;
		case 6: {
			char *name = NULL, *value = NULL;
			(void) parse_equal_string(buf, &name, &value);
			break;
		}
		default:
			(void) pbs_isjobid(buf);
			(void) check_job_name(buf, 0);
			(void) check_job_name(buf, 1);
			break;
	}
	free(buf);
	return 0;
}
