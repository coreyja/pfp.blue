use maud::{html, Markup, Render};

pub struct InputField {
    pub name: String,
    pub label: Option<String>,
    pub placeholder: Option<String>,
    pub value: Option<String>,
    pub input_type: String,
    pub required: bool,
    pub icon: Option<String>,
    pub hidden: bool,
}

impl InputField {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            label: None,
            placeholder: None,
            value: None,
            input_type: "text".to_string(),
            required: false,
            icon: None,
            hidden: false,
        }
    }

    pub fn label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    pub fn placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = Some(placeholder.to_string());
        self
    }

    pub fn value(mut self, value: &str) -> Self {
        self.value = Some(value.to_string());
        self
    }

    pub fn input_type(mut self, input_type: &str) -> Self {
        self.input_type = input_type.to_string();
        self
    }

    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    pub fn icon<I: Into<String>>(mut self, icon: I) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }
}

impl Render for InputField {
    fn render(&self) -> Markup {
        if self.hidden {
            return html! {
                input type="hidden" name=(self.name) value=(self.value.as_deref().unwrap_or("")) {}
            };
        }

        html! {
            div class="mb-4" {
                @if let Some(label) = &self.label {
                    label for=(self.name) class="block text-sm font-medium text-gray-700 mb-1" { (label) }
                }

                @if let Some(icon) = &self.icon {
                    div class="relative" {
                        div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" {
                            (maud::PreEscaped(icon))
                        }
                        input
                            type=(self.input_type)
                            name=(self.name)
                            id=(self.name)
                            value=(self.value.as_deref().unwrap_or(""))
                            placeholder=(self.placeholder.as_deref().unwrap_or(""))
                            class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-gray-900"
                            required[self.required] {}
                    }
                } @else {
                    input
                        type=(self.input_type)
                        name=(self.name)
                        id=(self.name)
                        value=(self.value.as_deref().unwrap_or(""))
                        placeholder=(self.placeholder.as_deref().unwrap_or(""))
                        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-gray-900"
                        required[self.required] {}
                }
            }
        }
    }
}

pub struct Form {
    pub action: String,
    pub method: String,
    pub content: Box<dyn Render>,
    pub extra_classes: Option<String>,
}

impl Form {
    pub fn new(action: &str, method: &str, content: impl Render + 'static) -> Self {
        Self {
            action: action.to_string(),
            method: method.to_string(),
            content: Box::new(content),
            extra_classes: None,
        }
    }

    pub fn extra_classes(mut self, classes: &str) -> Self {
        self.extra_classes = Some(classes.to_string());
        self
    }
}

impl Render for Form {
    fn render(&self) -> Markup {
        let extra_classes = self.extra_classes.as_deref().unwrap_or("");
        
        html! {
            form action=(self.action) method=(self.method) class={"space-y-4 " (extra_classes)} {
                (self.content.render())
            }
        }
    }
}

pub struct ToggleSwitch {
    pub name: String,
    pub label: String,
    pub description: Option<String>,
    pub checked: bool,
}

impl ToggleSwitch {
    pub fn new(name: &str, label: &str, checked: bool) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            description: None,
            checked,
        }
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
}

impl Render for ToggleSwitch {
    fn render(&self) -> Markup {
        html! {
            div class="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm" {
                div {
                    p class="font-medium text-gray-900" { (self.label) }
                    @if let Some(description) = &self.description {
                        p class="text-sm text-gray-500" { (description) }
                    }
                }

                label class="relative inline-flex items-center cursor-pointer" {
                    @if self.checked {
                        input type="checkbox" name=(self.name) value="true" checked class="sr-only peer" {}
                    } @else {
                        input type="checkbox" name=(self.name) value="true" class="sr-only peer" {}
                    }
                    span class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" {}
                }
            }
        }
    }
}