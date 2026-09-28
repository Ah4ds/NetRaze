use netraze_core::{KerberosFinding, KerberosFindingKind, KerberosTargetError};

use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerberosAction {
    None,
    ExportHashcat,
    ExportTicket,
}

pub struct KerberosView<'a> {
    pub endpoint: &'a str,
    pub realm: &'a str,
    pub findings: &'a [KerberosFinding],
    pub errors: &'a [KerberosTargetError],
    pub error: Option<&'a str>,
    pub cred_label: Option<&'a str>,
    pub artifacts_available: bool,
    pub ticket_available: bool,
}

pub fn show(ui: &mut egui::Ui, view: KerberosView<'_>) -> KerberosAction {
    let mut action = KerberosAction::None;
    ui.label(
        egui::RichText::new("🎟 Kerberos assessment")
            .size(15.0)
            .strong()
            .color(theme::FG),
    );
    ui.add_space(6.0);
    egui::Grid::new("kerberos_summary_grid")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("KDC").small().color(theme::MUTED));
            ui.monospace(view.endpoint);
            ui.end_row();
            ui.label(egui::RichText::new("Realm").small().color(theme::MUTED));
            ui.monospace(view.realm);
            ui.end_row();
            ui.label(egui::RichText::new("Login As").small().color(theme::MUTED));
            ui.label(view.cred_label.unwrap_or("(none)"));
            ui.end_row();
        });

    if let Some(error) = view.error {
        ui.add_space(8.0);
        ui.colored_label(theme::ERROR, error);
        return action;
    }

    let as_rep_count = view
        .findings
        .iter()
        .filter(|finding| finding.kind == KerberosFindingKind::AsRepRoast)
        .count();
    let service_count = view.findings.len().saturating_sub(as_rep_count);
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        summary_badge(ui, "AS-REP", as_rep_count);
        summary_badge(ui, "Service tickets", service_count);
        summary_badge(ui, "Errors", view.errors.len());
    });

    ui.add_space(10.0);
    ui.separator();
    ui.label(
        egui::RichText::new("FINDINGS")
            .small()
            .strong()
            .color(theme::ACC),
    );
    if view.findings.is_empty() {
        ui.label(
            egui::RichText::new("No roastable principals were returned.")
                .small()
                .color(theme::MUTED),
        );
    } else {
        egui::ScrollArea::vertical()
            .id_salt("kerberos_findings")
            .max_height(260.0)
            .show(ui, |ui| {
                for finding in view.findings {
                    let kind = match finding.kind {
                        KerberosFindingKind::AsRepRoast => "AS-REP",
                        KerberosFindingKind::Kerberoast => "TGS",
                    };
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(kind).strong().color(theme::WARNING));
                            ui.monospace(&finding.principal);
                        });
                        if let Some(spn) = &finding.service_principal_name {
                            ui.monospace(spn);
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "etype {} · Hashcat mode {}",
                                finding.encryption_type, finding.hashcat_mode
                            ))
                            .small()
                            .color(theme::MUTED),
                        );
                    });
                }
            });
    }

    if !view.errors.is_empty() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("TARGET ERRORS")
                .small()
                .strong()
                .color(theme::ERROR),
        );
        for error in view.errors {
            ui.label(
                egui::RichText::new(format!("{}: {}", error.target, error.message))
                    .small()
                    .color(theme::ERROR),
            );
        }
    }

    ui.add_space(12.0);
    if ui
        .add_enabled(
            view.artifacts_available,
            egui::Button::new("Export Hashcat material…"),
        )
        .clicked()
    {
        action = KerberosAction::ExportHashcat;
    }
    if ui
        .add_enabled(
            view.ticket_available,
            egui::Button::new("Export TGT as ccache/kirbi…"),
        )
        .clicked()
    {
        action = KerberosAction::ExportTicket;
    }
    ui.label(
        egui::RichText::new(if view.artifacts_available {
            "Export is explicit; the file is created with owner-only permissions on Unix."
        } else {
            "Sensitive ticket material is session-only and is unavailable after reloading a workspace."
        })
        .small()
        .color(theme::MUTED),
    );
    action
}

fn summary_badge(ui: &mut egui::Ui, label: &str, count: usize) {
    egui::Frame::NONE
        .fill(theme::ELEV_2)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(7, 4))
        .show(ui, |ui| {
            ui.label(format!("{label}: {count}"));
        });
}
