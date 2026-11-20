export type UsageBlocker = 'billing_unavailable' | 'entitlement_unavailable' | 'cost_evidence_unavailable' | 'usage_budget_exceeded';
export type UsageResult = { ok: true; reservation_id: string; replay: boolean } | { ok: false; code: UsageBlocker };

type Account = { period_start: string; period_end: string; budget_microusd: number; reserved_microusd: number; settled_microusd: number };

/** All chargeable boundaries must call this before an external side effect. */
export async function reserveUsage(db: D1Database, input: { workspaceId: string; userId: string; boundary: 'production_render'|'publish'|'storage'; idempotencyKey: string; requestHash: string; estimateMicrousd: number; at: string; id: string; ledgerId: string }): Promise<UsageResult> {
  const entitlement = await db.prepare(`SELECT e.* FROM workspace_plan_entitlements e JOIN plan_catalogs p ON p.id=e.plan_id JOIN billing_evidence b ON b.id=p.billing_evidence_id JOIN billing_evidence pr ON pr.id=p.pricing_evidence_id JOIN billing_evidence en ON en.id=e.entitlement_evidence_id WHERE e.workspace_id=?1 AND e.status='active' AND e.period_start<=?2 AND e.period_end>?2 AND p.status='enabled' AND b.status='verified' AND pr.status='verified' AND en.status='verified' AND (b.expires_at IS NULL OR b.expires_at>?2) AND (pr.expires_at IS NULL OR pr.expires_at>?2) AND (en.expires_at IS NULL OR en.expires_at>?2)`).bind(input.workspaceId,input.at).first();
  if (!entitlement) return { ok:false, code:'billing_unavailable' };
  if (!Number.isSafeInteger(input.estimateMicrousd) || input.estimateMicrousd < 0) return { ok:false, code:'cost_evidence_unavailable' };
  const existing = await db.prepare('SELECT id,request_hash FROM usage_reservations WHERE workspace_id=?1 AND idempotency_key=?2').bind(input.workspaceId,input.idempotencyKey).first<{id:string;request_hash:string}>();
  if (existing) return existing.request_hash===input.requestHash ? {ok:true,reservation_id:existing.id,replay:true} : {ok:false,code:'usage_budget_exceeded'};
  const account = await db.prepare('SELECT * FROM usage_period_accounts WHERE workspace_id=?1 AND user_id=?2 AND period_start<=?3 AND period_end>?3').bind(input.workspaceId,input.userId,input.at).first<Account>();
  if (!account) return {ok:false,code:'entitlement_unavailable'};
  const changed = await db.prepare('UPDATE usage_period_accounts SET reserved_microusd=reserved_microusd+?1,version=version+1,updated_at=?2 WHERE workspace_id=?3 AND user_id=?4 AND period_start=?5 AND reserved_microusd+settled_microusd+?1<=budget_microusd').bind(input.estimateMicrousd,input.at,input.workspaceId,input.userId,account.period_start).run();
  if (!changed.meta.changes) return {ok:false,code:'usage_budget_exceeded'};
  await db.batch([db.prepare('INSERT INTO usage_reservations(id,workspace_id,user_id,period_start,idempotency_key,boundary,estimate_microusd,status,request_hash,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,\'reserved\',?8,?9,?9)').bind(input.id,input.workspaceId,input.userId,account.period_start,input.idempotencyKey,input.boundary,input.estimateMicrousd,input.requestHash,input.at),db.prepare('INSERT INTO usage_ledger(id,reservation_id,workspace_id,user_id,kind,amount_microusd,uncertainty,detail,created_at) VALUES(?1,?2,?3,?4,\'reserve\',?5,\'estimated\',?6,?7)').bind(input.ledgerId,input.id,input.workspaceId,input.userId,input.estimateMicrousd,JSON.stringify({boundary:input.boundary}),input.at)]);
  return {ok:true,reservation_id:input.id,replay:false};
}

export async function usageSummary(db: D1Database, workspaceId: string, at: string) {
  const entitlement = await db.prepare(`SELECT e.status,e.period_start,e.period_end,p.code,p.display_name,p.allowance_microusd FROM workspace_plan_entitlements e JOIN plan_catalogs p ON p.id=e.plan_id WHERE e.workspace_id=?1 AND e.status='active' AND e.period_start<=?2 AND e.period_end>?2 AND p.status='enabled'`).bind(workspaceId,at).first();
  const accounts = await db.prepare('SELECT user_id,allowance_microusd,budget_microusd,reserved_microusd,settled_microusd,period_start,period_end FROM usage_period_accounts WHERE workspace_id=?1 AND period_start<=?2 AND period_end>?2').bind(workspaceId,at).all();
  const ledger = await db.prepare('SELECT kind,amount_microusd,uncertainty,detail,created_at FROM usage_ledger WHERE workspace_id=?1 ORDER BY created_at DESC LIMIT 100').bind(workspaceId).all();
  const policy = await db.prepare('SELECT monthly_limit_microusd,custom_limit_microusd,upgrade_threshold_percent FROM usage_budget_policies WHERE workspace_id=?1').bind(workspaceId).first();
  return { billing_status: entitlement ? 'available' : 'billing_unavailable', entitlement: entitlement ?? null, policy: policy ?? null, accounts: accounts.results, ledger: ledger.results, uncertainty: entitlement ? 'estimated_or_verified_only' : 'unknown', blocker: entitlement ? null : { code:'billing_unavailable', message:'No verified billing, pricing, and entitlement evidence is active.' } };
}

/** Provider failures and user cancellation release the exact reservation once. */
export async function releaseUsage(db: D1Database, reservationId: string, reason: string, at: string, ledgerId: string) {
  const row = await db.prepare("SELECT * FROM usage_reservations WHERE id=?1 AND status='reserved'").bind(reservationId).first<{id:string;workspace_id:string;user_id:string;period_start:string;estimate_microusd:number}>();
  if (!row) return false;
  await db.batch([db.prepare("UPDATE usage_period_accounts SET reserved_microusd=reserved_microusd-?1,version=version+1,updated_at=?2 WHERE workspace_id=?3 AND user_id=?4 AND period_start=?5 AND reserved_microusd>=?1").bind(row.estimate_microusd,at,row.workspace_id,row.user_id,row.period_start),db.prepare("UPDATE usage_reservations SET status='released',released_at=?1,release_reason=?2,updated_at=?1 WHERE id=?3 AND status='reserved'").bind(at,reason,row.id),db.prepare("INSERT INTO usage_ledger(id,reservation_id,workspace_id,user_id,kind,amount_microusd,uncertainty,detail,created_at) VALUES(?1,?2,?3,?4,'release',?5,'verified',?6,?7)").bind(ledgerId,row.id,row.workspace_id,row.user_id,row.estimate_microusd,JSON.stringify({reason}),at)]);
  return true;
}

/** Settlement requires independently obtained provider cost evidence. */
export async function settleUsage(db: D1Database, reservationId: string, actualMicrousd: number, evidenceId: string, at: string, ledgerId: string) {
  if (!Number.isSafeInteger(actualMicrousd) || actualMicrousd < 0) throw new Error('invalid actual usage');
  const row = await db.prepare("SELECT r.* FROM usage_reservations r JOIN billing_evidence e ON e.id=?2 WHERE r.id=?1 AND r.status='reserved' AND e.status='verified' AND e.evidence_kind='pricing' AND (e.expires_at IS NULL OR e.expires_at>?3)").bind(reservationId,evidenceId,at).first<{id:string;workspace_id:string;user_id:string;period_start:string;estimate_microusd:number}>();
  if (!row) return false;
  const account = await db.prepare('UPDATE usage_period_accounts SET reserved_microusd=reserved_microusd-?1,settled_microusd=settled_microusd+?2,version=version+1,updated_at=?3 WHERE workspace_id=?4 AND user_id=?5 AND period_start=?6 AND reserved_microusd>=?1 AND settled_microusd+?2<=budget_microusd').bind(row.estimate_microusd,actualMicrousd,at,row.workspace_id,row.user_id,row.period_start).run();
  if (!account.meta.changes) return false;
  await db.batch([db.prepare("UPDATE usage_reservations SET status='settled',settled_at=?1,updated_at=?1 WHERE id=?2 AND status='reserved'").bind(at,row.id),db.prepare("INSERT INTO usage_ledger(id,reservation_id,workspace_id,user_id,kind,amount_microusd,uncertainty,evidence_id,detail,created_at) VALUES(?1,?2,?3,?4,'settle',?5,'verified',?6,?7,?8)").bind(ledgerId,row.id,row.workspace_id,row.user_id,actualMicrousd,evidenceId,JSON.stringify({estimated_microusd:row.estimate_microusd}),at)]);
  return true;
}
