use crate::error::Error;
use crate::ice::ice_gather::ice_gatherer::ICEGatherer;
use crate::ice::ice_gather::ice_gatherer_state::ICEGathererState;
use crate::ice::ice_gather::ICEGatherOptions;
use media_engine::*;
use setting_engine::*;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;

pub mod media_engine;
pub mod setting_engine;

/// API bundles the global functions of the WebRTC and ORTC API.
/// Some of these functions are also exported globally using the
/// defaultAPI object. Note that the global version of the API
/// may be phased out in the future.
pub struct Api {
    setting_engine: SettingEngine,
    media_engine: MediaEngine,
    //TODO: interceptor   interceptor.Interceptor
}

impl Api {
    /// new_ice_gatherer creates a new NewICEGatherer.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub fn new_ice_gatherer(&self, opts: ICEGatherOptions) -> Result<ICEGatherer, Error> {
        let mut validated_servers = vec![];
        if !opts.ice_servers.is_empty() {
            for server in &opts.ice_servers {
                let url = server.urls()?;
                validated_servers.extend(url);
            }
        }

        Ok(ICEGatherer {
            state: Arc::new(AtomicU8::new(ICEGathererState::New as u8)),
            gather_policy: opts.ice_gather_policy,
            validated_servers,
            setting_engine: self.setting_engine.clone(),
            ..Default::default()
        })
    }
}

pub struct ApiBuilder {
    api: Api,
}

impl Default for ApiBuilder {
    fn default() -> Self {
        ApiBuilder {
            api: Api {
                setting_engine: SettingEngine::default(),
                media_engine: MediaEngine::default(),
            },
        }
    }
}

impl ApiBuilder {
    pub fn new() -> Self {
        ApiBuilder::default()
    }

    pub fn build(self) -> Api {
        self.api
    }

    /// WithSettingEngine allows providing a SettingEngine to the API.
    /// Settings should not be changed after passing the engine to an API.
    pub fn with_setting_engine(mut self, setting_engine: SettingEngine) -> Self {
        self.api.setting_engine = setting_engine;
        self
    }

    /// WithMediaEngine allows providing a MediaEngine to the API.
    /// Settings can be changed after passing the engine to an API.
    pub fn with_media_engine(mut self, media_engine: MediaEngine) -> Self {
        self.api.media_engine = media_engine;
        self
    }

    //TODO:
    // WithInterceptorRegistry allows providing Interceptors to the API.
    // Settings should not be changed after passing the registry to an API.
    /*pub WithInterceptorRegistry(interceptorRegistry *interceptor.Registry) func(a *API) {
        return func(a *API) {
            a.interceptor = interceptorRegistry.Build()
        }
    }*/
}