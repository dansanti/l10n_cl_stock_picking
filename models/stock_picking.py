# -*- coding: utf-8 -*-
from openerp import osv, models, fields, api, _
from openerp.osv import fields as old_fields
from openerp.exceptions import except_orm, UserError
import openerp.addons.decimal_precision as dp
import logging
_logger = logging.getLogger(__name__)

class StockPicking(models.Model):
    _inherit = "stock.picking"

    def get_document_class_default(self, document_classes):
        if self.turn_issuer.vat_affected not in ['SI', 'ND']:
            exempt_ids = [
                self.env.ref('l10n_cl_invoice.dc_y_f_dtn').id,
                self.env.ref('l10n_cl_invoice.dc_y_f_dte').id]
            for document_class in document_classes:
                if document_class.sii_document_class_id.id in exempt_ids:
                    document_class_id = document_class.id
                    break
                else:
                    document_class_id = document_classes.ids[0]
        else:
            document_class_id = document_classes.ids[0]
        return document_class_id

    @api.onchange('journal_id', 'company_id')
    def _set_available_issuer_turns(self):
        for rec in self:
            if rec.company_id:
                available_turn_ids = rec.company_id.company_activities_ids
                for turn in available_turn_ids:
                    rec.turn_issuer = turn

    def do_new_transfer(self, cr, uid, ids, context=None):
        super(StockPicking,self).do_new_transfer(cr, uid, ids, context=context)
        picking = self.pool.get('stock.picking').browse(cr,uid,ids,context=context)
        if not picking.sii_document_number and picking.picking_type_id.sequence_id.is_dte:
            picking.sii_document_number = int(picking.name)
            document_number = (picking.picking_type_id.sii_document_class_id.doc_code_prefix or '') + picking.sii_document_number
            picking.name = document_number

    @api.one
    @api.onchange('pack_operation_product_ids', 'currency_id', 'company_id')
    def _compute_amount(self):
        if self.pack_operation_product_ids and self.state not in ['draft']:
            for operation in self.pack_operation_product_ids:
                self.amount_untaxed += operation.subtotal
                if operation.operation_line_tax_ids:
                    taxes = operation.operation_line_tax_ids.compute_all(operation.price_unit, self.currency_id, operation.qty_done, product=operation.product_id, partner=self.partner_id)['taxes']
                    for tax in taxes:
                        self.amount_tax +=tax['amount']
            self.amount_total = self.amount_untaxed + self.amount_tax
        elif self.move_lines:
            for move in self.move_lines:
                self.amount_untaxed += move.subtotal
                if move.move_line_tax_ids:
                    taxes = move.move_line_tax_ids.compute_all(move.price_unit, self.currency_id, move.product_uom_qty, product=move.product_id, partner=self.partner_id)['taxes']
                    for tax in taxes:
                        self.amount_tax +=tax['amount']
            self.amount_total = self.amount_untaxed + self.amount_tax

    amount_untaxed = fields.Float(compute='_compute_amount',
                                  digits_compute=dp.get_precision('Account'),
                                  string='Untaxed Amount')
    amount_tax = fields.Float(compute='_compute_amount',
                              digits_compute=dp.get_precision('Account'),
                              string='Taxes')
    amount_total = fields.Float(compute='_compute_amount',
                                digits_compute=dp.get_precision('Account'),
                                string='Total')
    currency_id = fields.Many2one('res.currency', string='Currency',
        required=True, readonly=True, states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')
    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together')

    turn_issuer = fields.Many2one(
        'partner.activities',
        'Giro Emisor', store=True, required=False,
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})

    partner_turn = fields.Many2one(
        'partner.activities',
        'Giro',
        store=True,
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})
    sii_document_number = fields.Char(
        string='Document Number',
        copy=False,
        readonly=True,)
    responsability_id = fields.Many2one(
        'sii.responsability',
        string='Responsability',
        related='partner_id.responsability_id',
        store=True,
        )
    formated_vat = fields.Char(
        string='Responsability',
        related='partner_id.formated_vat',)

    next_number = fields.Integer(
        related='picking_type_id.sequence_id.number_next_actual',
        string='Next Document Number',
        readonly=True)
    use_documents = fields.Boolean(
        string='Use Documents?',
        readonly=True)
    reference =fields.One2many('stock.picking.referencias','stock_picking_id', readonly=True, states={'draft': [('readonly', False)]}, )
    transport_type = fields.Selection(
        [('2','Despacho por cuenta de empresa'),('1','Despacho por cuenta del cliente'),('3','Despacho Externo'),('0','Sin Definir')],
        string="Tipo de Despacho",
        required=True,
        default="2",
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})
    move_reason = fields.Selection(
        [('1','Operación constituye venta'),('2','Ventas por efectuar'), ('3','Consignaciones'),('4','Entrega Gratuita'),('5','Traslados Internos'),('6','Otros traslados no venta'),('7','Guía de Devolución'),('8','Traslado para exportación'),('9','Ventas para exportación')],
        string='Razón del traslado',
        default="1",
        required=True,
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})
    vehicle = fields.Many2one('fleet.vehicle', string="Vehículo",readonly=True, states={'draft': [('readonly', False)]},)
    chofer= fields.Many2one('res.partner', string="Chofer",readonly=True, states={'draft': [('readonly', False)]},)
    patente = fields.Char(string="Patente",readonly=True, states={'draft': [('readonly', False)]},)
    contact_id = fields.Many2one('res.partner',string="Contacto",readonly=True, states={'draft': [('readonly', False)]},)

    @api.onchange('vehicle')
    def _setChofer(self):
        self.chofer = self.vehicle.driver_id
        self.patente = self.vehicle.license_plate

    @api.onchange('carrier_id')
    def _setChoferFromCarrier(self):
        self.chofer = self.carrier_id.partner_id

    @api.onchange('pack_operation_product_ids')
    def _setValues(self):
        for rec in self:
            if rec.pack_operation_product_ids:
                for m in rec.pack_operation_product_ids:
                    for l in rec.move_lines_related:
                        if l.product_id.id == m.product_id.id:
                            m.price_unit = l.price_unit
                            m.discount = l.discount
                            m.operation_line_tax_ids = l.move_line_tax_ids
                if not m.price_unit > 0 or not m.name:
                    m.price_unit = m.product_id.lst_price
                    if not m.name:
                    	m.name = m.product_id.name
                    m.operation_line_tax_ids = m.product_id.taxes_id # @TODO mejorar asignación

class StockPickingType(models.Model):

    _inherit = 'stock.picking.type'
    sii_document_class_id = fields.Many2one(
            'sii.document_class',
            string='Document Type',
            copy=False,
            store=True)


class Referencias(models.Model):
    _name = 'stock.picking.referencias'

    origen = fields.Char(string="Origin")
    sii_referencia_TpoDocRef =  fields.Many2one('sii.document_class',
        string="SII Reference Document Type")
    date = fields.Date(string="Fecha de la referencia")
    stock_picking_id = fields.Many2one('stock.picking', ondelete='cascade',index=True,copy=False,string="Documento")

class StockPackOperation(models.Model):
    _inherit = "stock.pack.operation"

    def create(self, cr, uid, vals,context=None):
        picking_id = self.pool.get('stock.picking').browse(cr,uid,vals['picking_id'],context=context)
        for o in picking_id.move_lines:
            if vals['product_id'] == o.product_id.id:
                vals['name'] = o.name
                vals['price_unit'] = o.price_unit
                vals['subtotal'] = o.subtotal
                vals['discount'] = o.discount
                vals['operation_line_tax_ids'] = o.move_line_tax_ids.ids

        super(StockPackOperation,self).create(cr,uid,vals,context=context)

    @api.depends('picking_id.move_lines_related')
    @api.onchange('name', 'qty_done')
    def _setValues(self):
        for rec in self:
            for l in rec.picking_id.move_lines_related:
                if l.product_id.id == rec.product_id.id:
                    rec.price_unit = l.price_unit
                    rec.discount = l.discount
                    rec.operation_line_tax_ids = l.move_line_tax_ids
            if not rec.price_unit > 0 or not rec.name:
            	if not rec.name:
            		rec.name = rec.product_id.name
                rec.price_unit = rec.product_id.lst_price
                rec.operation_line_tax_ids = rec.product_id.taxes_id # @TODO mejorar asignación

    name = fields.Char(string="Nombre")

    subtotal = fields.Float(
        compute='_compute_amount', digits_compute=dp.get_precision('Account'),
        string='Subtotal')
    price_unit = fields.Float(digits_compute=dp.get_precision('Product Price'),
                                   string='Price')
    price_untaxed = fields.Float( digits_compute=dp.get_precision('Product Price'),
        string='Price Untaxed')

    operation_line_tax_ids = fields.Many2many('account.tax',
        'operation_line_tax', 'operation_line_id', 'tax_id',
            string='Taxes', domain=[('type_tax_use','!=','none'), '|', ('active', '=', False), ('active', '=', True)], oldname='invoice_line_tax_id')
    discount = fields.Float(digits_compute=dp.get_precision('Discount'),
                                 string='Discount (%)')

    @api.onchange('price_unit','qty_done','product_id','operation_line_tax_ids')
    def _compute_amount(self):
        for rec in self:
            currency = rec.picking_id.currency_id or None
            price = rec.price_unit * (1 - (rec.discount or 0.0) / 100.0)
            taxes = False
            if rec.operation_line_tax_ids:
                taxes = rec.operation_line_tax_ids.compute_all(price, currency, rec.qty_done, product=rec.product_id, partner=rec.picking_id.partner_id)
            rec.subtotal = price_subtotal_signed = taxes['total_excluded'] if taxes else rec.qty_done * price

class StockMove(models.Model):
    _inherit = 'stock.move'

    @api.model
    def create(self,vals):
        _logger.info(vals)
        #if 'linked_move_operation_ids' in vals:
        #    move = vals['linked_move_operation_ids'][0].move_id
        #    if move.procurement_id.sale_line_id:
        #        vals['operation_line_tax_ids'] = move.move_line_tax_ids.ids
        #        vals['price_untaxed'] = move.price_untaxed
        #        vals['price_unit'] = move.price_unit
        #        vals['discount'] = move.discount
        #        vals['subtotal'] = 0
        return super(StockMove,self).create(vals)

    @api.depends('picking_id.reference')
    @api.onchange('name')
    def _sale_prices(self):
        for rec in self:
            if rec.picking_id.reference:
                for ref in rec.picking_id.reference:
                    if ref.sii_referencia_TpoDocRef.sii_code in ['34','33']:# factura venta
                        inv = self.env['account.invoice'].search([('sii_document_number','=',ref.origen)])
                        for l in inv.invoice_lines:
                            if l.product_id.id == rec.product_id.id:
                                rec.price_unit = l.price_unit
                                rec.subtotal = l.subtotal
                                rec.discount = l.discount
                                rec.move_line_tax_ids = l.invoice_line_tax_ids
            if not rec.price_unit > 0 or not rec.name:
                if not rec.name:
                    rec.name = rec.product_id.name
                rec.price_unit = rec.product_id.lst_price
                rec.move_line_tax_ids = rec.product_id.taxes_id # @TODO mejorar asignación

    @api.onchange('name','product_id','move_line_tax_ids','product_uom_qty')
    def _compute_amount(self):
        for rec in self:
            currency = rec.picking_id.currency_id or None
            price = rec.price_unit * (1 - (rec.discount or 0.0) / 100.0)
            taxes = False
            if rec.move_line_tax_ids:
                taxes = rec.move_line_tax_ids.compute_all(price, currency, rec.product_uom_qty, product=rec.product_id, partner=rec.picking_id.partner_id)
            rec.subtotal = price_subtotal_signed = taxes['total_excluded'] if taxes else rec.product_uom_qty * price

    name = fields.Char(string="Nombre")

    subtotal = fields.Float(
        compute='_compute_amount', digits_compute=dp.get_precision('Product Price'),
        string='Subtotal')

    price_unit = fields.Float( digits_compute=dp.get_precision('Product Price'),
                                   string='Price')
    price_untaxed = fields.Float(
        compute='_sale_prices', digits_compute=dp.get_precision('Product Price'),
        string='Price Untaxed')

    move_line_tax_ids = fields.Many2many('account.tax',
        'move_line_tax_ids', 'move_line_id', 'tax_id',
            string='Taxes', domain=[('type_tax_use','!=','none'), '|', ('active', '=', False), ('active', '=', True)], oldname='invoice_line_tax_id')

    discount = fields.Float(digits_compute=dp.get_precision('Discount'),
                                 string='Discount (%)')
