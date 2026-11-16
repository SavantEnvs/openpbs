/* Known-answer checks over the OpenPBS parsers and the DIS wire codec that the fuzz targets exercise. */
#include "memxport.h"
#include <stdio.h>
#include "pbs_ifl.h"
#include "pbs_error.h"
#include "libpbs.h"
#include "libutil.h"
#include "list_link.h"
#include "server_limits.h"
#include "attribute.h"
#include "batch_request.h"
#include "grunt.h"
#include "cmds.h"
#include "pbs_client_thread.h"

extern int dis_request_read(int sfds, struct batch_request *request);

static int passed, failed;

#define CHECK(cond)                                                 \
	do {                                                        \
		if (cond) {                                         \
			passed++;                                   \
		} else {                                            \
			failed++;                                   \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		}                                                   \
	} while (0)

#define STREQ(a, b) ((a) != NULL && strcmp((a), (b)) == 0)

static void
test_select_spec(void)
{
	char s1[] = "2:ncpus=4:mem=1gb";
	char s2[] = "ncpus=1";
	char s3[] = "1:ncpus=2+3:mem=4gb";
	char s4[] = "nodeA:ncpus=8:mem=2gb";
	int nchk = 0, nelem = 0, nkve = 0, dflt = 0, hp = 0, nl = 0, nlkv = 0;
	struct key_value_pair *kv = NULL;
	char *node = NULL, *last = NULL, *tok;

	CHECK(parse_chunk_r(s1, &nchk, &nelem, &nkve, &kv, &dflt) == 0);
	CHECK(nchk == 2);
	CHECK(nelem == 2);
	CHECK(dflt == 0);
	CHECK(kv != NULL && STREQ(kv[0].kv_keyw, "ncpus") && STREQ(kv[0].kv_val, "4"));
	CHECK(kv != NULL && STREQ(kv[1].kv_keyw, "mem") && STREQ(kv[1].kv_val, "1gb"));
	free(kv);

	kv = NULL;
	nkve = 0;
	CHECK(parse_chunk_r(s2, &nchk, &nelem, &nkve, &kv, &dflt) == 0);
	CHECK(nchk == 1);
	CHECK(nelem == 1);
	CHECK(dflt == 1);
	CHECK(kv != NULL && STREQ(kv[0].kv_keyw, "ncpus") && STREQ(kv[0].kv_val, "1"));
	free(kv);

	tok = parse_plus_spec_r(s3, &last, &hp);
	CHECK(STREQ(tok, "1:ncpus=2"));
	tok = parse_plus_spec_r(last, &last, &hp);
	CHECK(STREQ(tok, "3:mem=4gb"));
	tok = parse_plus_spec_r(last, &last, &hp);
	CHECK(tok == NULL);

	kv = NULL;
	CHECK(parse_node_resc_r(s4, &node, &nl, &nlkv, &kv) == 0);
	CHECK(STREQ(node, "nodeA"));
	CHECK(nl == 2);
	CHECK(kv != NULL && STREQ(kv[0].kv_keyw, "ncpus") && STREQ(kv[0].kv_val, "8"));
	CHECK(kv != NULL && STREQ(kv[1].kv_keyw, "mem") && STREQ(kv[1].kv_val, "2gb"));
	free(kv);
}

static void
test_execvnode_seq(void)
{
	char *c, **tofree = NULL, **u;
	char in[] = "(n1:ncpus=1)~(n1:ncpus=1)~(n1:ncpus=1)~(n2:mem=1gb)";
	char seq[] = "4#(n2:mem=1gb){3}(n1:ncpus=1){0-2}";

	c = condense_execvnode_seq(in);
	CHECK(STREQ(c, seq));
	free(c);

	CHECK(get_execvnodes_count(seq) == 4);

	u = unroll_execvnode_seq(seq, &tofree);
	CHECK(u != NULL && STREQ(u[0], "(n1:ncpus=1)") && STREQ(u[2], "(n1:ncpus=1)") && STREQ(u[3], "(n2:mem=1gb)") && u[4] == NULL);
	free_execvnode_seq(tofree);
	free(u);
}

static void
test_attr_decode(void)
{
	attribute a;
	pbs_list_head head;
	svrattrl *sl;

	memset(&a, 0, sizeof(a));
	CHECK(decode_l(&a, "x", NULL, "42") == 0);
	CHECK(a.at_val.at_long == 42);
	CHECK(decode_l(&a, "x", NULL, "4x2") != 0);

	memset(&a, 0, sizeof(a));
	CHECK(decode_size(&a, "x", NULL, "2kb") == 0);
	CHECK(a.at_val.at_size.atsv_num == 2 && a.at_val.at_size.atsv_shift == 10);

	memset(&a, 0, sizeof(a));
	CHECK(decode_time(&a, "x", NULL, "01:02:03") == 0);
	CHECK(a.at_val.at_long == 3723);

	memset(&a, 0, sizeof(a));
	CHECK(decode_b(&a, "x", NULL, "true") == 0);
	CHECK(a.at_val.at_long == 1);
	memset(&a, 0, sizeof(a));
	CHECK(decode_b(&a, "x", NULL, "n") == 0);
	CHECK(a.at_val.at_long == 0);

	memset(&a, 0, sizeof(a));
	CHECK(decode_str(&a, "x", NULL, "hello") == 0);
	CHECK(STREQ(a.at_val.at_str, "hello"));
	CLEAR_HEAD(head);
	CHECK(encode_str(&a, &head, "x", NULL, ATR_ENCODE_CLIENT, NULL) > 0);
	sl = (svrattrl *) GET_NEXT(head);
	CHECK(sl != NULL && STREQ(sl->al_value, "hello") && STREQ(sl->al_name, "x"));
	free_attrlist(&head);
	free_str(&a);

	memset(&a, 0, sizeof(a));
	CHECK(decode_arst(&a, "x", NULL, "a,b,c") == 0);
	CHECK(a.at_val.at_arst != NULL && a.at_val.at_arst->as_usedptr == 3);
	CHECK(a.at_val.at_arst != NULL && STREQ(a.at_val.at_arst->as_string[1], "b"));
	free_arst(&a);
}

static void
test_cli_parse(void)
{
	char *seq = NULL, *parent = NULL, *cur = NULL, *q = NULL, *s = NULL;
	char jobid[] = "123.myserver";
	char dest[] = "workq@host1";
	char range[] = "1-9:2";
	char bad[] = "1-";

	CHECK(parse_jobid(jobid, &seq, &parent, &cur) == 0);
	CHECK(STREQ(seq, "123") && STREQ(parent, "myserver"));
	free(seq);
	free(parent);
	free(cur);

	CHECK(parse_destination_id(dest, &q, &s) == 0);
	CHECK(STREQ(q, "workq") && STREQ(s, "host1"));
	free(q);
	free(s);

	CHECK(chk_Jrange(range) == 0);
	CHECK(chk_Jrange(bad) != 0);

	CHECK(pbs_isjobid("12.srv") == 1);
	CHECK(pbs_isjobid("srv") == 0);
	CHECK(check_job_name("myjob", 1) == 0);
	CHECK(check_job_name("1job", 1) != 0);
}

static unsigned char wire[4096];
static size_t wirelen;

static void
capture(void)
{
	CHECK(dis_flush(MX_FD) == 0);
	wirelen = mx_outlen < sizeof(wire) ? mx_outlen : sizeof(wire);
	memcpy(wire, mx_out, wirelen);
	mx_close();
}

static struct batch_request *
decode_wire(void)
{
	struct batch_request *r = (struct batch_request *) calloc(1, sizeof(*r));

	r->prot = PROT_TPP;
	mx_open(wire, wirelen);
	r->rq_type = 0;
	int rc = dis_request_read(MX_FD, r);
	CHECK(rc == 0);
	mx_close();
	return r;
}

static void
test_dis_roundtrip(void)
{
	struct batch_request *r;
	struct attropl at;
	svrattrl *sl;

	memset(&at, 0, sizeof(at));
	at.name = "queue_type";
	at.value = "execution";
	at.op = SET;
	mx_open(NULL, 0);
	CHECK(encode_DIS_ReqHdr(MX_FD, PBS_BATCH_Manager, "alice") == 0);
	CHECK(encode_DIS_Manage(MX_FD, MGR_CMD_SET, MGR_OBJ_QUEUE, "workq", &at) == 0);
	CHECK(encode_DIS_ReqExtend(MX_FD, "force") == 0);
	capture();
	CHECK(wirelen > 6 && memcmp(wire, "PKTV1", 5) == 0);
	r = decode_wire();
	CHECK(r->rq_type == PBS_BATCH_Manager);
	CHECK(STREQ(r->rq_user, "alice"));
	CHECK(r->rq_ind.rq_manager.rq_cmd == MGR_CMD_SET);
	CHECK(r->rq_ind.rq_manager.rq_objtype == MGR_OBJ_QUEUE);
	CHECK(STREQ(r->rq_ind.rq_manager.rq_objname, "workq"));
	sl = (svrattrl *) GET_NEXT(r->rq_ind.rq_manager.rq_attr);
	CHECK(sl != NULL && STREQ(sl->al_name, "queue_type") && STREQ(sl->al_value, "execution"));
	free_attrlist(&r->rq_ind.rq_manager.rq_attr);
	CHECK(STREQ(r->rq_extend, "force"));
	free(r->rq_extend);
	free(r);

	mx_open(NULL, 0);
	CHECK(encode_DIS_ReqHdr(MX_FD, PBS_BATCH_RunJob, "bob") == 0);
	CHECK(encode_DIS_Run(MX_FD, "5.svr", "nodeA/0", 0) == 0);
	CHECK(encode_DIS_ReqExtend(MX_FD, NULL) == 0);
	capture();
	r = decode_wire();
	CHECK(r->rq_type == PBS_BATCH_RunJob);
	CHECK(STREQ(r->rq_user, "bob"));
	CHECK(STREQ(r->rq_ind.rq_run.rq_jid, "5.svr"));
	CHECK(STREQ(r->rq_ind.rq_run.rq_destin, "nodeA/0"));
	free(r->rq_ind.rq_run.rq_destin);
	free(r);
}

int
main(void)
{
	(void) pbs_client_thread_init_thread_context();
	test_select_spec();
	test_execvnode_seq();
	test_attr_decode();
	test_cli_parse();
	test_dis_roundtrip();
	printf("SELFTEST passed=%d failed=%d\n", passed, failed);
	return failed == 0 ? 0 : 1;
}
