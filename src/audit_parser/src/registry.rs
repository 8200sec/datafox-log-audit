// Copyright 2026 DataFox Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;

use crate::{parser::Parser, types::RawLogInput};

/// Ordered, self-describing parser lookup. New parsers register themselves — the
/// dispatcher never grows a vendor switch. Priority decides order; `detect`
/// decides a match; a fallback parser catches everything else.
#[derive(Default)]
pub struct ParserRegistry {
    parsers: Vec<Arc<dyn Parser>>,
    fallback: Option<Arc<dyn Parser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a parser. Duplicate `id` returns an error (id is the stable identity).
    pub fn register(&mut self, parser: Arc<dyn Parser>) -> anyhow::Result<()> {
        if self.parsers.iter().any(|p| p.id() == parser.id()) {
            anyhow::bail!("parser id already registered: {}", parser.id());
        }
        self.parsers.push(parser);
        Ok(())
    }

    pub fn set_fallback(&mut self, parser: Arc<dyn Parser>) {
        self.fallback = Some(parser);
    }

    pub fn lookup(&self, id: &str) -> Option<Arc<dyn Parser>> {
        self.parsers.iter().find(|p| p.id() == id).cloned()
    }

    pub fn fallback(&self) -> Option<Arc<dyn Parser>> {
        self.fallback.clone()
    }

    /// All registered parsers, highest priority first (stable for equal priority).
    pub fn list(&self) -> Vec<Arc<dyn Parser>> {
        let mut sorted = self.parsers.clone();
        sorted.sort_by_key(|p| std::cmp::Reverse(p.priority()));
        sorted
    }

    /// Parsers whose `detect` accepts the input, in priority order.
    pub fn detect(&self, input: &RawLogInput) -> Vec<Arc<dyn Parser>> {
        self.list()
            .into_iter()
            .filter(|p| p.detect(input))
            .collect()
    }
}
