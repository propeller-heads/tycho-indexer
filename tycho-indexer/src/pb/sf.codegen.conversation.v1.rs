// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserInput {
    /// Monotonic incrementing number
    #[prost(uint32, tag="1")]
    pub msg_id: u32,
    #[prost(uint32, tag="2")]
    pub from_msg_id: u32,
    #[prost(string, tag="3")]
    pub from_action_id: ::prost::alloc::string::String,
    #[prost(oneof="user_input::Entry", tags="11, 15, 17, 18, 16, 20, 21")]
    pub entry: ::core::option::Option<user_input::Entry>,
}
/// Nested message and enum types in `UserInput`.
pub mod user_input {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TextInput {
        #[prost(string, tag="1")]
        pub value: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LocalFile {
        #[prost(bytes="vec", tag="1")]
        pub value: ::prost::alloc::vec::Vec<u8>,
        /// Error can be set by the client to indicate an issue when trying to read the file,
        /// the error comes from the client side. The server can inspect that to decide what
        /// to do next if there is an error.
        ///
        /// If an error is set, the \[value\] field will be empty and not populated, so implementor
        /// should check for that first.
        #[prost(string, optional, tag="2")]
        pub error: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Start {
        /// generator_id routes the conversation to the right generator backend
        #[prost(string, tag="1")]
        pub generator_id: ::prost::alloc::string::String,
        /// Hydrate will be present when the user already has a pre-built state, and wants to continue from there.
        #[prost(message, optional, tag="2")]
        pub hydrate: ::core::option::Option<Hydrate>,
        /// Version of the supported protocol by the client.
        /// If the code generator requires a more recent client, then it should also report an error, or try to downgrade the conversation protocol.
        #[prost(uint32, tag="3")]
        pub version: u32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Hydrate {
        /// If `saved_payload` is none, then just start a new session.
        ///
        /// JSON state from a previous session, to continue where we left off.
        #[prost(string, tag="1")]
        pub saved_state: ::prost::alloc::string::String,
        /// HMAC sig from the server for the saved_payload. Optional.
        #[prost(bytes="vec", tag="2")]
        pub signature: ::prost::alloc::vec::Vec<u8>,
        /// whatever
        #[prost(uint32, tag="3")]
        pub last_msg_id: u32,
        /// Whether to continue, or to reset the conversation. If this is `false`, it means try to continue (the connection was merely disconnected). Otherwise, it means we're starting anew. Let's give all the options and directions.
        #[prost(bool, tag="4")]
        pub reset_conversation: bool,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Upload {
        #[prost(string, tag="1")]
        pub mime_type: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub filename: ::prost::alloc::string::String,
        #[prost(bytes="vec", tag="3")]
        pub content: ::prost::alloc::vec::Vec<u8>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Selection {
        #[prost(string, tag="1")]
        pub label: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub value: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Confirmation {
        #[prost(bool, tag="1")]
        pub affirmative: bool,
    }
    /// Deprecated: this isn't used
    ///
    /// This is only to return a message to the server that the files were downloaded
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DownloadedFiles {
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Entry {
        #[prost(message, tag="11")]
        Start(Start),
        #[prost(message, tag="15")]
        TextInput(TextInput),
        #[prost(message, tag="17")]
        Selection(Selection),
        #[prost(message, tag="18")]
        Confirmation(Confirmation),
        #[prost(message, tag="16")]
        File(Upload),
        /// Deprecated: we don't use this.
        #[prost(message, tag="20")]
        DownloadedFiles(DownloadedFiles),
        #[prost(message, tag="21")]
        LocalFile(LocalFile),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SystemOutput {
    /// unique message ID
    #[prost(uint32, tag="1")]
    pub msg_id: u32,
    #[prost(uint32, tag="2")]
    pub from_msg_id: u32,
    /// the type of action that is required here, tags like "confirm_final" or "select_subgraph" or "select_network", so the UI can hook into the response the user will take here.
    #[prost(string, tag="3")]
    pub action_id: ::prost::alloc::string::String,
    /// to be saved each step, if connection drops, Init back with this state
    #[prost(string, tag="4")]
    pub state: ::prost::alloc::string::String,
    /// Optional, or future ?
    #[prost(bytes="vec", tag="5")]
    pub state_signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(oneof="system_output::Entry", tags="15, 16, 17, 18, 21, 19, 20, 22")]
    pub entry: ::core::option::Option<system_output::Entry>,
}
/// Nested message and enum types in `SystemOutput`.
pub mod system_output {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Message {
        #[prost(string, tag="1")]
        pub markdown: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub style: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ImageWithText {
        #[prost(string, tag="1")]
        pub img_url: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub markdown: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ListSelect {
        /// Deprecated: use `action_id` instead
        #[prost(string, tag="1")]
        pub id: ::prost::alloc::string::String,
        /// These need to be the same length
        #[prost(string, repeated, tag="2")]
        pub labels: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        #[prost(string, repeated, tag="3")]
        pub values: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        /// Optional. If present, same length as the labels and values. Shows a small icon aside of the label text.
        #[prost(string, repeated, tag="4")]
        pub image_urls: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        /// In Markdown format
        #[prost(string, tag="6")]
        pub instructions: ::prost::alloc::string::String,
        #[prost(bool, tag="8")]
        pub select_many: bool,
        #[prost(enumeration="list_select::SelectType", tag="7")]
        pub select_type: i32,
        #[prost(string, tag="5")]
        pub select_button_label: ::prost::alloc::string::String,
        #[prost(string, tag="9")]
        pub default_value: ::prost::alloc::string::String,
    }
    /// Nested message and enum types in `ListSelect`.
    pub mod list_select {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum SelectType {
            Dropdown = 0,
            Buttons = 1,
        }
        impl SelectType {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    SelectType::Dropdown => "DROPDOWN",
                    SelectType::Buttons => "BUTTONS",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "DROPDOWN" => Some(Self::Dropdown),
                    "BUTTONS" => Some(Self::Buttons),
                    _ => None,
                }
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TextInput {
        #[prost(string, tag="8")]
        pub prompt: ::prost::alloc::string::String,
        /// Markdown
        #[prost(string, tag="1")]
        pub description: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub placeholder: ::prost::alloc::string::String,
        /// Pre-filled the textbox
        #[prost(string, tag="9")]
        pub default_value: ::prost::alloc::string::String,
        /// Number of lines if multiline box.
        #[prost(int32, tag="3")]
        pub multi_line: i32,
        #[prost(string, tag="4")]
        pub validation_regexp: ::prost::alloc::string::String,
        #[prost(string, tag="5")]
        pub validation_error_message: ::prost::alloc::string::String,
        #[prost(string, tag="6")]
        pub submit_button_label: ::prost::alloc::string::String,
        /// icon name or image_url
        #[prost(string, tag="7")]
        pub submit_button_icon: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LocalFile {
        #[prost(string, tag="8")]
        pub prompt: ::prost::alloc::string::String,
        /// Markdown
        #[prost(string, tag="1")]
        pub description: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub placeholder: ::prost::alloc::string::String,
        /// Pre-filled the textbox
        #[prost(string, tag="9")]
        pub default_value: ::prost::alloc::string::String,
        #[prost(string, tag="6")]
        pub submit_button_label: ::prost::alloc::string::String,
        /// icon name or image_url
        #[prost(string, tag="7")]
        pub submit_button_icon: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Loading {
        #[prost(bool, tag="1")]
        pub loading: bool,
        /// other fields to format the loader and whatnot
        #[prost(string, tag="2")]
        pub label: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DownloadFiles {
        #[prost(message, repeated, tag="1")]
        pub files: ::prost::alloc::vec::Vec<DownloadFile>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DownloadFile {
        #[prost(string, tag="1")]
        pub filename: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub r#type: ::prost::alloc::string::String,
        #[prost(bytes="vec", tag="3")]
        pub content: ::prost::alloc::vec::Vec<u8>,
        #[prost(string, tag="4")]
        pub description: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Confirm {
        #[prost(string, tag="1")]
        pub prompt: ::prost::alloc::string::String,
        #[prost(string, tag="4")]
        pub description: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub accept_button_label: ::prost::alloc::string::String,
        #[prost(string, tag="3")]
        pub decline_button_label: ::prost::alloc::string::String,
        #[prost(enumeration="confirm::Button", tag="5")]
        pub default_button: i32,
    }
    /// Nested message and enum types in `Confirm`.
    pub mod confirm {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
        #[repr(i32)]
        pub enum Button {
            Unset = 0,
            Confirm = 1,
            Decline = 2,
        }
        impl Button {
            /// String value of the enum field names used in the ProtoBuf definition.
            ///
            /// The values are not transformed in any way and thus are considered stable
            /// (if the ProtoBuf definition does not change) and safe for programmatic use.
            pub fn as_str_name(&self) -> &'static str {
                match self {
                    Button::Unset => "UNSET",
                    Button::Confirm => "CONFIRM",
                    Button::Decline => "DECLINE",
                }
            }
            /// Creates an enum from field names used in the ProtoBuf definition.
            pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                match value {
                    "UNSET" => Some(Self::Unset),
                    "CONFIRM" => Some(Self::Confirm),
                    "DECLINE" => Some(Self::Decline),
                    _ => None,
                }
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Entry {
        /// Markdown message to display
        #[prost(message, tag="15")]
        Message(Message),
        #[prost(message, tag="16")]
        ImageWithText(ImageWithText),
        #[prost(message, tag="17")]
        ListSelect(ListSelect),
        #[prost(message, tag="18")]
        TextInput(TextInput),
        #[prost(message, tag="21")]
        Confirm(Confirm),
        #[prost(message, tag="19")]
        Loading(Loading),
        #[prost(message, tag="20")]
        DownloadFiles(DownloadFiles),
        #[prost(message, tag="22")]
        LocalFile(LocalFile),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DiscoveryRequest {
    #[prost(string, tag="1")]
    pub search_terms: ::prost::alloc::string::String,
    /// Version sent to the codegen service, which is incremental (0,1,2...).
    /// It is used to force users to upgrade after breaking changes between the CLI and the codegen server.
    #[prost(uint64, tag="2")]
    pub client_version: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DiscoveryResponse {
    #[prost(message, repeated, tag="1")]
    pub generators: ::prost::alloc::vec::Vec<discovery_response::Generator>,
}
/// Nested message and enum types in `DiscoveryResponse`.
pub mod discovery_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Generator {
        #[prost(string, tag="1")]
        pub id: ::prost::alloc::string::String,
        #[prost(string, tag="2")]
        pub title: ::prost::alloc::string::String,
        #[prost(string, tag="3")]
        pub description: ::prost::alloc::string::String,
        #[prost(string, tag="4")]
        pub icon_url: ::prost::alloc::string::String,
        /// if not the same as this one
        #[prost(string, tag="5")]
        pub endpoint: ::prost::alloc::string::String,
        #[prost(string, tag="6")]
        pub group: ::prost::alloc::string::String,
    }
}
include!("sf.codegen.conversation.v1.tonic.rs");
// @@protoc_insertion_point(module)