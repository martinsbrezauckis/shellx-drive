// Take a look at the license at the top of the repository in the LICENSE file.

use crate::{prelude::*, Binding, Object};

impl Binding {
    #[doc(alias = "get_source")]
    pub fn source(&self) -> Option<Object> {
        self.property("source")
    }

    #[doc(alias = "get_target")]
    pub fn target(&self) -> Option<Object> {
        self.property("target")
    }
}

#[cfg(test)]
mod test {
    use crate::{prelude::*, subclass::prelude::*};

    #[test]
    fn binding_rejects_same_property_and_drops_transform() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct DropProbe(Arc<AtomicUsize>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let source = TestObject::default();
        let dropped = Arc::new(AtomicUsize::new(0));
        let probe = DropProbe(dropped.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source
                .bind_property("name", &source, "name")
                .transform_to_with_values(move |_, value| {
                    let _ = &probe;
                    Some(value.clone())
                })
                .build()
        }));
        assert!(result.is_err());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn binding_rejects_invalid_property_permissions() {
        let source = TestObject::default();
        let target = TestObject::default();
        for (from, to, bidirectional) in [
            ("write-only", "enabled", false),
            ("enabled", "read-only", false),
            ("enabled", "construct-only", false),
            ("read-only", "enabled", true),
            ("construct-only", "enabled", true),
            ("enabled", "write-only", true),
        ] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let binding = source.bind_property(from, &target, to);
                if bidirectional {
                    binding.bidirectional().build()
                } else {
                    binding.build()
                }
            }));
            assert!(
                result.is_err(),
                "invalid binding {from} -> {to} was accepted"
            );
        }
    }

    #[test]
    fn binding_boolean_inversion_preserves_custom_transforms() {
        let source = TestObject::default();
        let target = TestObject::default();
        let invalid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            source
                .bind_property("name", &target, "name")
                .invert_boolean()
                .build()
        }));
        assert!(invalid.is_err());

        let custom = source
            .bind_property("name", &target, "name")
            .invert_boolean()
            .transform_to(|_, value: String| Some(format!("custom:{value}")))
            .build();
        source.set_name("value");
        assert_eq!(target.name(), "custom:value");
        custom.unbind();

        let boolean = source
            .bind_property("enabled", &target, "enabled")
            .invert_boolean()
            .sync_create()
            .build();
        assert!(!source.enabled());
        assert!(target.enabled());
        source.set_enabled(true);
        assert!(!target.enabled());
        boolean.unbind();
    }

    #[test]
    fn binding() {
        let source = TestObject::default();
        let target = TestObject::default();

        assert!(source.find_property("name").is_some());
        source
            .bind_property("name", &target, "name")
            .bidirectional()
            .build();

        source.set_name("test_source_name");
        assert_eq!(source.name(), target.name());

        target.set_name("test_target_name");
        assert_eq!(source.name(), target.name());
    }

    #[test]
    fn binding_to_transform_with_values() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "name")
            .sync_create()
            .transform_to_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some(format!("{value} World").to_value())
            })
            .transform_from_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some(format!("{value} World").to_value())
            })
            .build();

        source.set_name("Hello");
        assert_eq!(target.name(), "Hello World");
    }

    #[test]
    fn binding_from_transform_with_values() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "name")
            .sync_create()
            .bidirectional()
            .transform_to_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some(format!("{value} World").to_value())
            })
            .transform_from_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some(format!("{value} World").to_value())
            })
            .build();

        target.set_name("Hello");
        assert_eq!(source.name(), "Hello World");
    }

    #[test]
    fn binding_to_transform_ref() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "name")
            .sync_create()
            .transform_to_with_values(|_binding, value| {
                Some(format!("{} World", value.get::<&str>().unwrap()).to_value())
            })
            .transform_from_with_values(|_binding, value| {
                Some(format!("{} World", value.get::<&str>().unwrap()).to_value())
            })
            .build();

        source.set_name("Hello");
        assert_eq!(target.name(), "Hello World");
    }

    #[test]
    fn binding_to_transform_owned_ref() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "name")
            .sync_create()
            .transform_to(|_binding, value: String| Some(format!("{value} World")))
            .transform_from_with_values(|_binding, value| {
                Some(format!("{} World", value.get::<&str>().unwrap()).to_value())
            })
            .build();

        source.set_name("Hello");
        assert_eq!(target.name(), "Hello World");
    }

    #[test]
    fn binding_from_transform() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "name")
            .sync_create()
            .bidirectional()
            .transform_to(|_binding, value: String| Some(format!("{value} World")))
            .transform_from(|_binding, value: String| Some(format!("{value} World")))
            .build();

        target.set_name("Hello");
        assert_eq!(source.name(), "Hello World");
    }

    #[test]
    fn binding_to_transform_with_values_change_type() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "enabled")
            .sync_create()
            .transform_to_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some((value == "Hello").to_value())
            })
            .transform_from_with_values(|_binding, value| {
                let value = value.get::<bool>().unwrap();
                Some((if value { "Hello" } else { "World" }).to_value())
            })
            .build();

        source.set_name("Hello");
        assert!(target.enabled());

        source.set_name("Hello World");
        assert!(!target.enabled());
    }

    #[test]
    fn binding_from_transform_values_change_type() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "enabled")
            .sync_create()
            .bidirectional()
            .transform_to_with_values(|_binding, value| {
                let value = value.get::<&str>().unwrap();
                Some((value == "Hello").to_value())
            })
            .transform_from_with_values(|_binding, value| {
                let value = value.get::<bool>().unwrap();
                Some((if value { "Hello" } else { "World" }).to_value())
            })
            .build();

        target.set_enabled(true);
        assert_eq!(source.name(), "Hello");
        target.set_enabled(false);
        assert_eq!(source.name(), "World");
    }

    #[test]
    fn binding_to_transform_change_type() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "enabled")
            .sync_create()
            .transform_to(|_binding, value: String| Some(value == "Hello"))
            .transform_from(|_binding, value: bool| Some(if value { "Hello" } else { "World" }))
            .build();

        source.set_name("Hello");
        assert!(target.enabled());

        source.set_name("Hello World");
        assert!(!target.enabled());
    }

    #[test]
    fn binding_from_transform_change_type() {
        let source = TestObject::default();
        let target = TestObject::default();

        source
            .bind_property("name", &target, "enabled")
            .sync_create()
            .bidirectional()
            .transform_to(|_binding, value: String| Some(value == "Hello"))
            .transform_from(|_binding, value: bool| Some(if value { "Hello" } else { "World" }))
            .build();

        target.set_enabled(true);
        assert_eq!(source.name(), "Hello");
        target.set_enabled(false);
        assert_eq!(source.name(), "World");
    }

    mod imp {
        use std::cell::RefCell;

        use once_cell::sync::Lazy;

        use super::*;
        use crate as glib;

        #[derive(Debug, Default)]
        pub struct TestObject {
            pub name: RefCell<String>,
            pub enabled: RefCell<bool>,
        }

        #[crate::object_subclass]
        impl ObjectSubclass for TestObject {
            const NAME: &'static str = "TestBinding";
            type Type = super::TestObject;
        }

        impl ObjectImpl for TestObject {
            fn properties() -> &'static [crate::ParamSpec] {
                static PROPERTIES: Lazy<Vec<crate::ParamSpec>> = Lazy::new(|| {
                    vec![
                        crate::ParamSpecString::builder("name")
                            .explicit_notify()
                            .build(),
                        crate::ParamSpecBoolean::builder("enabled")
                            .explicit_notify()
                            .build(),
                        crate::ParamSpecBoolean::builder("read-only")
                            .read_only()
                            .build(),
                        crate::ParamSpecBoolean::builder("write-only")
                            .write_only()
                            .build(),
                        crate::ParamSpecBoolean::builder("construct-only")
                            .construct_only()
                            .build(),
                    ]
                });
                PROPERTIES.as_ref()
            }

            fn property(&self, _id: usize, pspec: &crate::ParamSpec) -> crate::Value {
                let obj = self.obj();
                match pspec.name() {
                    "name" => obj.name().to_value(),
                    "enabled" | "read-only" | "write-only" | "construct-only" => {
                        obj.enabled().to_value()
                    }
                    _ => unimplemented!(),
                }
            }

            fn set_property(&self, _id: usize, value: &crate::Value, pspec: &crate::ParamSpec) {
                let obj = self.obj();
                match pspec.name() {
                    "name" => obj.set_name(value.get().unwrap()),
                    "enabled" | "read-only" | "write-only" | "construct-only" => {
                        obj.set_enabled(value.get().unwrap())
                    }
                    _ => unimplemented!(),
                };
            }
        }
    }

    crate::wrapper! {
        pub struct TestObject(ObjectSubclass<imp::TestObject>);
    }

    impl Default for TestObject {
        fn default() -> Self {
            crate::Object::new()
        }
    }

    impl TestObject {
        fn name(&self) -> String {
            self.imp().name.borrow().clone()
        }

        fn set_name(&self, name: &str) {
            if name != self.imp().name.replace(name.to_string()).as_str() {
                self.notify("name");
            }
        }

        fn enabled(&self) -> bool {
            *self.imp().enabled.borrow()
        }

        fn set_enabled(&self, enabled: bool) {
            if enabled != self.imp().enabled.replace(enabled) {
                self.notify("enabled");
            }
        }
    }
}
