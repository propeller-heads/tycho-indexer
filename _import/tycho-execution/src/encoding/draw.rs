pub struct Post {
    state: Option<Box<dyn State>>,
    content: String,
}

impl Post {
    pub fn new() -> Post {
        println!("Draft has been created.\n");
        Post {
            state: Some(Box::new(Draft {})),
            content: String::new(),
        }
    }

    // This behavior doesn’t depend on the state the post is in, so it’s not part of the state pattern.
    pub fn add_text(&mut self, text: &str) {
        self.content.push_str(text);
    }

    // State patten. Because we call the state methods here, the implementation of Post will never
    // have to change.
    pub fn content(&self) -> &str {
        self.state.as_ref().unwrap().content(self)
    }

    pub fn request_review(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.request_review())
        }
    }

    pub fn approve(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.approve())
        }
    }
}

trait State {
    fn request_review(self: Box<Self>) -> Box<dyn State>;
    fn approve(self: Box<Self>) -> Box<dyn State>;

    fn content<'a>(&self, _post: &'a Post) -> &'a str {
        ""
    }
}

struct Draft {}

impl State for Draft {
    fn request_review(self: Box<Self>) -> Box<dyn State> {
        println!("Review has been requested.\n");
        Box::new(PendingReview {})
    }

    fn approve(self: Box<Self>) -> Box<dyn State> {
        self
    }
}

struct PendingReview {}

impl State for PendingReview {
    fn request_review(self: Box<Self>) -> Box<dyn State> {
        self
    }

    fn approve(self: Box<Self>) -> Box<dyn State> {
        println!("Post has been approved and published!\n");
        Box::new(Published {})
    }

}

struct Published {}

impl State for Published {
    fn request_review(self: Box<Self>) -> Box<dyn State> {
        self
    }

    fn approve(self: Box<Self>) -> Box<dyn State> {
        self
    }

    fn content<'a>(&self, post: &'a Post) -> &'a str {
        &post.content
    }
}

fn main() {
    let mut post = Post::new();

    post.add_text("I ate a salad for lunch today");

    println!(
        "Content: {}\n",
        post.content()
    );

    post.request_review();
    println!(
        "Content: {}\n",
        post.content()
    );

    post.approve();
    println!(
        "Content: {}\n",
        post.content()
    );
}