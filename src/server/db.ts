export interface Env { DB: D1Database; }

export type Role = "owner" | "admin" | "editor" | "reviewer" | "viewer";

export interface User { id: string; email: string; display_name: string; status: string; created_at: string; last_seen_at: string; }
export interface Membership { id: string; workspace_id: string; user_id: string; role: Role; status: string; }

export async function membership(db: D1Database, workspaceId: string, userId: string): Promise<Membership | null> {
  return db.prepare("SELECT id, workspace_id, user_id, role, status FROM memberships WHERE workspace_id = ? AND user_id = ? AND status = 'active'").bind(workspaceId, userId).first<Membership>();
}

export function publicUser(user: User) { return { id: user.id, email: user.email, display_name: user.display_name, status: user.status, created_at: user.created_at, last_seen_at: user.last_seen_at }; }
