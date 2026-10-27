//! Conversation settings: the message TTL and screen-capture protection.

use crate::core::ChatCore;
use crate::error::SdkError;
use crate::params::{MessageTtlChangeParams, MessageTtlRemoveParams, ScreenCaptureParams};
use crate::signatures::CURRENT_SIGNATURE_VERSION;
use crate::thrift::event::{
    ConversationMetadataChange, ConversationMetadataChangeEvent, DisableScreenCaptureBlocking,
    DisableScreenCaptureDetection, EnableScreenCaptureBlocking, EnableScreenCaptureDetection,
    MessageDurationChange, MessageDurationRemove, MessageEventDetail,
};
use crate::types::PreparedAction;

use super::{encode_detail, one_action, sign_named};

impl ChatCore {
    /// Sign a message-TTL change. The signature covers `ttl_msec` only.
    pub fn prepare_message_ttl_change(
        &self,
        params: &MessageTtlChangeParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        if params.ttl_msec < 0 {
            return Err(SdkError::InvalidInput(
                "ttl_msec is negative: pass the message TTL in milliseconds".into(),
            ));
        }
        let ttl = params.ttl_msec.to_string();
        let signature = sign_named(
            &ctx,
            "ConversationMetadataChangeEvent.MessageDurationChange",
            &[&ttl],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(ConversationMetadataChange::MessageDurationChange(
                MessageDurationChange {
                    ttl_msec: Some(params.ttl_msec),
                    apply_to_all_messages: None,
                },
            ))?,
        )?;
        Ok(one_action(signature))
    }

    /// Sign clearing a conversation's message TTL.
    pub fn prepare_message_ttl_remove(
        &self,
        params: &MessageTtlRemoveParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let signature = sign_named(
            &ctx,
            "ConversationMetadataChangeEvent.MessageDurationRemove",
            &[],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(ConversationMetadataChange::MessageDurationRemove(
                MessageDurationRemove {
                    current_ttl_msec: None,
                },
            ))?,
        )?;
        Ok(one_action(signature))
    }

    /// Sign one screen-capture setting change.
    ///
    /// Blocking and detection each have an enable and a disable event. The
    /// signed payload has no fields after the conversation id. Detection
    /// event names are the ones this SDK's verifier reconstructs.
    pub fn prepare_screen_capture(
        &self,
        params: &ScreenCaptureParams,
    ) -> Result<PreparedAction, SdkError> {
        let ctx = self.action_ctx(
            &params.conversation_id,
            params.sender_id.as_deref(),
            params.signing_key_version.as_deref(),
        )?;
        let signature = sign_named(
            &ctx,
            params.change.event_name(),
            &[],
            CURRENT_SIGNATURE_VERSION,
            metadata_detail(screen_capture_detail(params.change))?,
        )?;
        Ok(one_action(signature))
    }
}

fn metadata_detail(change: ConversationMetadataChange) -> Result<String, SdkError> {
    encode_detail(MessageEventDetail::ConversationMetadataChangeEvent(
        ConversationMetadataChangeEvent {
            conversation_metadata_change: Some(change),
        },
    ))
}

fn screen_capture_detail(change: crate::types::ScreenCaptureChange) -> ConversationMetadataChange {
    use crate::types::ScreenCaptureChange as Change;
    match change {
        Change::BlockingEnabled => {
            ConversationMetadataChange::EnableScreenCaptureBlocking(EnableScreenCaptureBlocking {
                placeholder: None,
            })
        }
        Change::BlockingDisabled => {
            ConversationMetadataChange::DisableScreenCaptureBlocking(DisableScreenCaptureBlocking {
                placeholder: None,
            })
        }
        Change::DetectionEnabled => {
            ConversationMetadataChange::EnableScreenCaptureDetection(EnableScreenCaptureDetection {
                placeholder: None,
            })
        }
        Change::DetectionDisabled => ConversationMetadataChange::DisableScreenCaptureDetection(
            DisableScreenCaptureDetection { placeholder: None },
        ),
    }
}
