use crate::wa_binary::BinaryNode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaMessageAddressingMode {
    Pn,
    Lid,
}

impl WaMessageAddressingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            WaMessageAddressingMode::Pn => "pn",
            WaMessageAddressingMode::Lid => "lid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupParticipant {
    pub id: String,
    pub phone_number: Option<String>,
    pub lid: Option<String>,
    pub username: Option<String>,
    pub admin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMetadata {
    pub id: String,
    pub notify: Option<String>,
    pub addressing_mode: WaMessageAddressingMode,
    pub subject: String,
    pub subject_owner: Option<String>,
    pub subject_owner_pn: Option<String>,
    pub subject_owner_username: Option<String>,
    pub subject_time: Option<u64>,
    pub size: usize,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub owner_pn: Option<String>,
    pub owner_username: Option<String>,
    pub owner_country_code: Option<String>,
    pub desc: Option<String>,
    pub desc_id: Option<String>,
    pub desc_owner: Option<String>,
    pub desc_owner_pn: Option<String>,
    pub desc_owner_username: Option<String>,
    pub desc_time: Option<u64>,
    pub linked_parent: Option<String>,
    pub restrict: bool,
    pub announce: bool,
    pub is_community: bool,
    pub is_community_announce: bool,
    pub join_approval_mode: bool,
    pub member_add_mode: bool,
    pub participants: Vec<GroupParticipant>,
    pub ephemeral_duration: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantAction {
    Add,
    Remove,
    Promote,
    Demote,
}

impl ParticipantAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParticipantAction::Add => "add",
            ParticipantAction::Remove => "remove",
            ParticipantAction::Promote => "promote",
            ParticipantAction::Demote => "demote",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRequestAction {
    Approve,
    Reject,
}

impl GroupRequestAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            GroupRequestAction::Approve => "approve",
            GroupRequestAction::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSetting {
    Announcement,
    NotAnnouncement,
    Locked,
    Unlocked,
}

impl GroupSetting {
    pub fn as_str(&self) -> &'static str {
        match self {
            GroupSetting::Announcement => "announcement",
            GroupSetting::NotAnnouncement => "not_announcement",
            GroupSetting::Locked => "locked",
            GroupSetting::Unlocked => "unlocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAddMode {
    AdminAdd,
    AllMemberAdd,
}

impl MemberAddMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberAddMode::AdminAdd => "admin_add",
            MemberAddMode::AllMemberAdd => "all_member_add",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinApprovalMode {
    On,
    Off,
}

impl JoinApprovalMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            JoinApprovalMode::On => "on",
            JoinApprovalMode::Off => "off",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantUpdateResult {
    pub status: String,
    pub jid: Option<String>,
    pub content: BinaryNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestParticipantUpdateResult {
    pub status: String,
    pub jid: Option<String>,
}
