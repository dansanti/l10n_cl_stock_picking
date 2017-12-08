# -*- coding: utf-8 -*-

from openerp import fields, models, api, _

class PickingToInvoiceD(models.Model):
    _inherit = 'account.invoice'

    def _get_pending_pickings(self ):
        for inv in self:
            if inv.type in ['out_invoice']:
                pickings = self.env['stock.picking'].search_count(
                    [
                        ('invoiced', '=', False),
                        ('sii_result', 'in', ['Proceso', 'Reparo']),
                        ('partner_id.commercial_partner_id', '=', inv.commercial_partner_id.id),
                    ]
                )
                inv.has_pending_pickings = pickings

    has_pending_pickings = fields.Integer(
        string="Pending Pickings",
        compute='_get_pending_pickings',
    )

    @api.multi
    def invoice_validate(self):
        result  = super(PickingToInvoiceD,self).invoice_validate()
        for inv in self:
            sp = False
            if inv.move_id:
                for ref in inv.referencias:
                    if ref.sii_referencia_TpoDocRef.sii_code in [ '56' ]:
                        sp = self.env['stock_picking'].search([('sii_document_number', '=', ref.origen)])
                if sp:
                    if inv.type in ['out_invoice']:
                        sp.invoiced = True
                    else:
                        sp.invoiced = False
        return result
