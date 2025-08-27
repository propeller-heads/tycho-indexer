use std::{str::FromStr, time::Instant};

use futures::StreamExt;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{CheckedSub, One, Pow};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Flex, Layout, Margin, Rect},
    style::{palette::tailwind, Color, Modifier, Style, Stylize},
    text::Text,
    widgets::{
        Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
    },
    DefaultTerminal, Frame,
};
use tokio::{select, sync::mpsc::Receiver};
use tracing::warn;
use tycho_common::{simulation::protocol_sim::ProtocolSim, Bytes};
use tycho_simulation::protocol::models::{ProtocolComponent, Update};

const INFO_TEXT: [&str; 2] = [
    "(Esc) quit | (↑) move up | (↓) move down | (↵) Toggle Quote | (+) Increase Quote Amount",
    "(-) Decrease Quote Amount | (z) Flip Quote Direction | (=) Enter Quote Amount",
];

const ITEM_HEIGHT: usize = 3;

struct TableColors {
    buffer_bg: Color,
    header_bg: Color,
    header_fg: Color,
    row_fg: Color,
    selected_row_style_fg: Color,
    selected_column_style_fg: Color,
    selected_cell_style_fg: Color,
    normal_row_color: Color,
    alt_row_color: Color,
    footer_border_color: Color,
}

impl TableColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            buffer_bg: tailwind::SLATE.c950,
            header_bg: color.c900,
            header_fg: tailwind::SLATE.c200,
            row_fg: tailwind::SLATE.c200,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            footer_border_color: color.c400,
        }
    }
}

struct Data {
    component: ProtocolComponent,
    state: Box<dyn ProtocolSim>,
    name: String,
    tokens: String,
    price: String,
}

impl Data {
    const fn ref_array(&self) -> [&String; 4] {
        [&self.name, &self.component.protocol_system, &self.tokens, &self.price]
    }
}

pub struct App {
    state: TableState,
    show_popup: bool,
    quote_amount: BigUint,
    zero2one: bool,
    items: Vec<Data>,
    rx: Receiver<Update>,
    scroll_state: ScrollbarState,
    colors: TableColors,
    input_mode: bool,
    input_buffer: String,
}

impl App {
    pub fn new(rx: Receiver<Update>) -> Self {
        let data_vec = Vec::new();
        Self {
            state: TableState::default().with_selected(0),
            show_popup: false,
            quote_amount: BigUint::one(),
            zero2one: true,
            rx,
            scroll_state: ScrollbarState::new(0),
            colors: TableColors::new(&tailwind::BLUE),
            items: data_vec,
            input_mode: false,
            input_buffer: String::new(),
        }
    }

    pub fn move_row(&mut self, direction: isize) {
        // Get current decimals, if any
        let current_decimals = self.state.selected().map(|idx| {
            let comp = &self.items[idx].component;
            if self.zero2one {
                comp.tokens[0].decimals
            } else {
                comp.tokens[1].decimals
            }
        });

        // Calculate the new index based on direction
        let new_index = match self.state.selected() {
            Some(i) => {
                ((i as isize + direction + self.items.len() as isize) % self.items.len() as isize)
                    as usize
            }
            None => 0,
        };

        // Update state and scroll position
        self.state.select(Some(new_index));
        self.scroll_state = self
            .scroll_state
            .position(new_index * ITEM_HEIGHT);

        // Adjust quote amount if decimals have changed
        if let Some(prev_decimals) = current_decimals {
            let comp = &self.items[new_index].component;
            let decimals = comp.tokens[if self.zero2one { 0 } else { 1 }].decimals;
            if decimals >= prev_decimals {
                self.quote_amount *= BigUint::from(10u64).pow(decimals - prev_decimals);
            } else {
                let new_amount =
                    self.quote_amount.clone() / BigUint::from(10u64).pow(prev_decimals - decimals);
                self.quote_amount =
                    if new_amount > BigUint::ZERO { new_amount } else { BigUint::one() };
            }
        }
    }

    pub fn update_data(&mut self, update: Update) {
        for (id, comp) in update.new_pairs.iter() {
            let name = format!("{comp_id:#042x}", comp_id = comp.id);
            let tokens = comp
                .tokens
                .iter()
                .map(|a| a.symbol.clone())
                .join("/");

            match update.states.get(id) {
                Some(state) => {
                    // Check if spot_price calculation is successful
                    match state.spot_price(&comp.tokens[0], &comp.tokens[1]) {
                        Ok(price) => {
                            self.items.push(Data {
                                component: comp.clone(),
                                state: state.clone(),
                                name,
                                tokens,
                                price: price.to_string(),
                            });
                        }
                        Err(_) => {
                            // Skip pools with spot_price errors
                            warn!(
                                "Skipping pool {comp_id} due to spot_price error",
                                comp_id = comp.id
                            );
                        }
                    }
                }
                None => {
                    warn!("Received update for unknown pool {comp_id}", comp_id = comp.id)
                }
            };
        }

        for (address, state) in update.states.iter() {
            let eth_address = Bytes::from_str(address).expect("Bad address");
            let entry = self
                .items
                .iter()
                .find_position(|e| e.component.id == eth_address);
            if let Some((index, _)) = entry {
                let row = &self.items[index];
                match state.spot_price(&row.component.tokens[0], &row.component.tokens[1]) {
                    Ok(price) => {
                        // Update the price and state if calculation is successful
                        let row = self.items.get_mut(index).unwrap();
                        row.price = price.to_string();
                        row.state = state.clone();
                    }
                    Err(_) => {
                        // Remove the pool if spot_price calculation fails
                        warn!("Removing pool {} due to spot_price error", address);
                        self.items.remove(index);
                    }
                }
            }
        }

        for comp in update.removed_pairs.values() {
            let entry = self
                .items
                .iter()
                .enumerate()
                .find(|(_, e)| e.component.id == comp.id);
            if let Some((idx, _)) = entry {
                self.items.remove(idx);
            }
        }
    }

    pub async fn run(mut self, mut terminal: DefaultTerminal) -> anyhow::Result<()> {
        let mut reader = event::EventStream::new();
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            select! {
                maybe_data = self.rx.recv() => {
                    if let Some(data) = maybe_data {
                        self.update_data(data);
                    }
                },
                maybe_event = reader.next() => {
                    if let Some(Ok(Event::Key(key))) = maybe_event {
                        if key.kind == KeyEventKind::Press {
                            if self.input_mode {
                                match key.code {
                                    KeyCode::Char(c) => {
                                        if c.is_ascii_digit() {
                                            self.input_buffer.push(c);
                                        }
                                    },
                                    KeyCode::Backspace => {
                                        self.input_buffer.pop();
                                    },
                                    KeyCode::Enter => {
                                        if let Ok(amount) = self.input_buffer.parse::<u64>() {
                                            self.quote_amount = BigUint::from(amount);
                                        }
                                        self.input_mode = false;
                                        self.input_buffer.clear();
                                    },
                                    KeyCode::Esc => {
                                        self.input_mode = false;
                                        self.input_buffer.clear();
                                    },
                                    _ => {}
                                }
                            } else {
                                match key.code {
                                    KeyCode::Char('q') | KeyCode::Esc => {
                                        if !self.show_popup {
                                            return Ok(())
                                        } else {
                                            self.show_popup = !self.show_popup
                                        }
                                    },
                                    KeyCode::Char('j') | KeyCode::Down => self.move_row(1),
                                    KeyCode::Char('+') => {
                                        self.modify_quote(true)
                                    },
                                    KeyCode::Char('-') => {
                                        self.modify_quote(false)
                                    },
                                    KeyCode::Char('z') => {
                                        self.zero2one = !self.zero2one;
                                        self.quote_amount = BigUint::one();
                                    }
                                    KeyCode::Char('k') | KeyCode::Up => self.move_row(-1),
                                    KeyCode::Char('=') => {
                                        self.input_mode = true;
                                        self.input_buffer.clear();
                                    },
                                    KeyCode::Enter => self.show_popup = !self.show_popup,
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            };
        }
    }

    fn modify_quote(&mut self, increase: bool) {
        if !self.show_popup {
            return;
        }

        if let Some(idx) = self.state.selected() {
            let comp = &self.items[idx].component;
            let decimals =
                if self.zero2one { comp.tokens[0].decimals } else { comp.tokens[1].decimals };
            if increase {
                self.quote_amount += BigUint::from(10u64).pow(decimals);
            } else {
                self.quote_amount = self
                    .quote_amount
                    .checked_sub(&BigUint::from(10u64).pow(decimals))
                    .unwrap_or(BigUint::one());
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let vertical = &Layout::vertical([Constraint::Min(5), Constraint::Length(4)]);
        let rects = vertical.split(frame.area());

        self.render_table(frame, rects[0]);
        self.render_scrollbar(frame, rects[0]);
        self.render_footer(frame, rects[1]);
        if self.items.is_empty() {
            self.render_loading(frame);
        }
        if self.show_popup {
            self.render_quote_popup(frame);
        }
        if self.input_mode {
            self.render_input_popup(frame);
        }
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header_style = Style::default()
            .fg(self.colors.header_fg)
            .bg(self.colors.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_row_style_fg);
        let selected_col_style = Style::default().fg(self.colors.selected_column_style_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_cell_style_fg);

        let header = ["Pool", "Protocol", "Tokens", "Price"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);
        let rows = self
            .items
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let color = match i % 2 {
                    0 => self.colors.normal_row_color,
                    _ => self.colors.alt_row_color,
                };
                let item = data.ref_array();
                item.into_iter()
                    .map(|content| Cell::from(Text::from(format!("\n{content}\n"))))
                    .collect::<Row>()
                    .style(
                        Style::new()
                            .fg(self.colors.row_fg)
                            .bg(color),
                    )
                    .height(ITEM_HEIGHT as u16)
            });
        let bar = " █ ";
        let t = Table::new(
            rows,
            [
                // + 1 is for padding.
                Constraint::Length(43),
                Constraint::Min(1),
                Constraint::Min(1),
                Constraint::Min(1),
            ],
        )
        .header(header)
        .row_highlight_style(selected_row_style)
        .column_highlight_style(selected_col_style)
        .cell_highlight_style(selected_cell_style)
        .highlight_symbol(Text::from(vec!["".into(), bar.into(), bar.into(), "".into()]))
        .bg(self.colors.buffer_bg)
        .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(t, area, &mut self.state);
    }

    fn render_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin { vertical: 1, horizontal: 1 }),
            &mut self.scroll_state,
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let info_footer = Paragraph::new(Text::from_iter(INFO_TEXT))
            .style(
                Style::new()
                    .fg(self.colors.row_fg)
                    .bg(self.colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.colors.footer_border_color)),
            );
        frame.render_widget(info_footer, area);
    }

    fn render_loading(&self, frame: &mut Frame) {
        let area = frame.area();

        let block = Block::bordered();
        let popup = Paragraph::new(Text::from("\nLOADING...\n"))
            .centered()
            .block(block);
        let area = popup_area(area, Constraint::Percentage(50), Constraint::Length(5));
        frame.render_widget(Clear, area);
        frame.render_widget(popup, area);
    }

    fn render_quote_popup(&self, frame: &mut Frame) {
        let area = frame.area();

        if let Some(idx) = self.state.selected() {
            if self.quote_amount > BigUint::ZERO {
                let comp = &self.items[idx].component;
                let state = &self.items[idx].state;
                let (token_in, token_out) = if self.zero2one {
                    (&comp.tokens[0], &comp.tokens[1])
                } else {
                    (&comp.tokens[1], &comp.tokens[0])
                };

                let start = Instant::now();
                let res = state.get_amount_out(self.quote_amount.clone(), token_in, token_out);
                let duration = start.elapsed();

                let text = res
                    .map(|data| {
                        format!(
                            "Swap Direction: {token_in_symbol} → {token_out_symbol}\nQuote amount: {quote_amount}\nReceived amount: {amount}\nGas: {gas}\nDuration: {duration:?}",
                            token_in_symbol = token_in.symbol,
                            token_out_symbol = token_out.symbol,
                            quote_amount = self.quote_amount,
                            amount = data.amount,
                            gas = data.gas
                        )
                    })
                    .unwrap_or_else(|err| format!("{err:?}"));

                let block = Block::bordered().title("Quote:");
                let popup = Paragraph::new(Text::from(text))
                    .block(block)
                    .wrap(Wrap { trim: false });
                let area = popup_area(area, Constraint::Percentage(50), Constraint::Percentage(50));
                frame.render_widget(Clear, area);
                frame.render_widget(popup, area);
            }
        }
    }

    fn render_input_popup(&self, frame: &mut Frame) {
        let area = frame.area();

        let text = format!(
            "Enter quote amount: {}\n\nPress Enter to confirm or Esc to cancel",
            self.input_buffer
        );
        let block = Block::bordered()
            .title("Quote Amount Input")
            .border_style(Style::new().fg(self.colors.footer_border_color));
        let input = Paragraph::new(Text::from(text))
            .block(block)
            .wrap(Wrap { trim: false })
            .style(
                Style::new()
                    .fg(self.colors.row_fg)
                    .bg(self.colors.buffer_bg),
            );
        let area = popup_area(area, Constraint::Percentage(50), Constraint::Length(8));
        frame.render_widget(Clear, area);
        frame.render_widget(input, area);
    }
}

/// helper function to create a centered rect using up certain percentage of the available rect `r`
fn popup_area(area: Rect, x: Constraint, y: Constraint) -> Rect {
    let vertical = Layout::vertical([y]).flex(Flex::Center);
    let horizontal = Layout::horizontal([x]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}
