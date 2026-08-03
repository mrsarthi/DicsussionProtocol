/**
 * @dicsussion/sdk — GroupService
 *
 * Group/channel management: creation, joining, leaving, and invite handling
 * per RFC 004 §7.3.
 */

import type { GroupInfo, GroupInvite } from './types.js';

/**
 * Group service for managing chat channels and group membership.
 */
export class GroupService {
  private readonly inviteCallbacks: Array<(invite: GroupInvite) => void> = [];

  async createGroup(_name: string, _members: string[]): Promise<GroupInfo> {
    throw new Error('GroupService.createGroup not yet implemented');
  }

  async joinGroup(_groupId: string): Promise<void> {
    throw new Error('GroupService.joinGroup not yet implemented');
  }

  async leaveGroup(_groupId: string): Promise<void> {
    throw new Error('GroupService.leaveGroup not yet implemented');
  }

  async getGroupInfo(_groupId: string): Promise<GroupInfo> {
    throw new Error('GroupService.getGroupInfo not yet implemented');
  }

  /**
   * Register a callback for group invite notifications.
   * @returns Unsubscribe function.
   */
  onInvite(callback: (invite: GroupInvite) => void): () => void {
    this.inviteCallbacks.push(callback);
    return () => {
      const idx = this.inviteCallbacks.indexOf(callback);
      if (idx >= 0) this.inviteCallbacks.splice(idx, 1);
    };
  }
}
