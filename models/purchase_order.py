# -*- coding: utf-8 -*-
from odoo import api, models, fields
from odoo.tools.translate import _
from odoo.exceptions import Warning
import logging
_logger = logging.getLogger(__name__)

class POL(models.Model):
    _inherit = 'purchase.order.line'

    @api.multi
    def _prepare_stock_moves(self, picking):
        result = super(POL, self)._prepare_stock_moves(picking)
        self.ensure_one()
        result.update({
                'price_unit': self.price_unit,
                'subtotal': self.subtotal,
                'discount': self.discount,
                'move_line_tax_ids': self.invoice_line_tax_ids,
                'currency_id': self.currency_id.id,
            })
        return result
