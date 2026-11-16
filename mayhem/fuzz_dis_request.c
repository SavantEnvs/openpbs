/* Server-side batch request decoder (DIS over PKTV1 packets) fed from an in-memory transport. */
#include "memxport.h"
#include "libpbs.h"
#include "list_link.h"
#include "server_limits.h"
#include "attribute.h"
#include "batch_request.h"
#include "pbs_error.h"

extern int dis_request_read(int sfds, struct batch_request *request);

static void
free_strings(char **arr, int n)
{
	if (arr == NULL)
		return;
	for (int i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

static void
free_nullterm(char **arr)
{
	if (arr == NULL)
		return;
	for (char **p = arr; *p; p++)
		free(*p);
	free(arr);
}

static void
free_attrs(pbs_list_head *head)
{
	if (head->ll_next != NULL)
		free_attrlist(head);
}

static void
free_pairs(pbs_list_head *head)
{
	struct rqfpair *p;

	if (head->ll_next == NULL)
		return;
	while ((p = (struct rqfpair *) GET_NEXT(*head)) != NULL) {
		delete_link(&p->fp_link);
		free(p->fp_local);
		free(p->fp_rmt);
		free(p);
	}
}

static void
free_request(struct batch_request *r)
{
	union indep_request *u = &r->rq_ind;

	free(r->rq_extend);
	switch (r->rq_type) {
		case PBS_BATCH_QueueJob:
		case PBS_BATCH_SubmitResv:
			free_attrs(&u->rq_queuejob.rq_attr);
			break;
		case PBS_BATCH_JobCred:
			free(u->rq_jobcred.rq_data);
			break;
		case PBS_BATCH_UserCred:
			free(u->rq_usercred.rq_data);
			break;
		case PBS_BATCH_jobscript:
		case PBS_BATCH_MvJobFile:
			free(u->rq_jobfile.rq_data);
			break;
		case PBS_BATCH_DeleteJob:
		case PBS_BATCH_DeleteResv:
		case PBS_BATCH_ResvOccurEnd:
		case PBS_BATCH_HoldJob:
		case PBS_BATCH_ModifyJob:
		case PBS_BATCH_ModifyJob_Async:
		case PBS_BATCH_ModifyResv:
		case PBS_BATCH_Manager:
		case PBS_BATCH_ReleaseJob:
			free_attrs(&u->rq_manager.rq_attr);
			break;
		case PBS_BATCH_DeleteJobList:
			free_nullterm(u->rq_deletejoblist.rq_jobslist);
			break;
		case PBS_BATCH_MessJob:
			free(u->rq_message.rq_text);
			break;
		case PBS_BATCH_RelnodesJob:
			free(u->rq_relnodes.rq_node_list);
			break;
		case PBS_BATCH_PySpawn:
			free_nullterm(u->rq_py_spawn.rq_argv);
			free_nullterm(u->rq_py_spawn.rq_envp);
			break;
		case PBS_BATCH_RunJob:
		case PBS_BATCH_AsyrunJob:
		case PBS_BATCH_AsyrunJob_ack:
		case PBS_BATCH_StageIn:
		case PBS_BATCH_ConfirmResv:
			free(u->rq_run.rq_destin);
			break;
		case PBS_BATCH_StatusJob:
		case PBS_BATCH_StatusNode:
		case PBS_BATCH_StatusResv:
		case PBS_BATCH_StatusQue:
		case PBS_BATCH_StatusSvr:
		case PBS_BATCH_StatusSched:
		case PBS_BATCH_StatusRsc:
		case PBS_BATCH_StatusHook:
			free(u->rq_status.rq_id);
			free_attrs(&u->rq_status.rq_attr);
			break;
		case PBS_BATCH_RegisterSched:
			free(u->rq_register_sched.rq_name);
			break;
		case PBS_BATCH_Rescq:
		case PBS_BATCH_ReserveResc:
		case PBS_BATCH_ReleaseResc:
			free_strings(u->rq_rescq.rq_list, u->rq_rescq.rq_num);
			break;
		case PBS_BATCH_DefSchReply:
			free(u->rq_defrpy.rq_id);
			free(u->rq_defrpy.rq_txt);
			break;
		case PBS_BATCH_SelectJobs:
		case PBS_BATCH_SelStat:
			free_attrs(&u->rq_select.rq_selattr);
			free_attrs(&u->rq_select.rq_rtnattr);
			break;
		case PBS_BATCH_PreemptJobs:
			free(u->rq_preempt.ppj_list);
			break;
		case PBS_BATCH_CopyFiles:
		case PBS_BATCH_DelFiles:
			free_pairs(&u->rq_cpyfile.rq_pair);
			break;
		case PBS_BATCH_CopyFiles_Cred:
		case PBS_BATCH_DelFiles_Cred:
			free_pairs(&u->rq_cpyfile_cred.rq_copyfile.rq_pair);
			free(u->rq_cpyfile_cred.rq_pcred);
			break;
		case PBS_BATCH_Cred:
			free(u->rq_cred.rq_cred_data);
			break;
	}
	free(r);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct batch_request *req = (struct batch_request *) calloc(1, sizeof(*req));

	if (req == NULL)
		return 0;
	req->prot = PROT_TPP; /* keeps dis_request_read from swapping our transport for the TCP one */
	mx_open(data, size);
	(void) dis_request_read(MX_FD, req);
	mx_close();
	free_request(req);
	return 0;
}
