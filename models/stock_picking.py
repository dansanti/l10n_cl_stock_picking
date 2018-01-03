# -*- coding: utf-8 -*-
from datetime import date, datetime
from odoo import osv, models, fields, api, _, SUPERUSER_ID
from odoo.exceptions import except_orm, UserError
import odoo.addons.decimal_precision as dp
from odoo.tools.float_utils import float_compare, float_round
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, DEFAULT_SERVER_DATE_FORMAT
import logging
_logger = logging.getLogger(__name__)

class StockPicking(models.Model):
    _inherit = "stock.picking"

    def get_document_class_default(self, document_classes):
        if self.turn_issuer.vat_affected not in ['SI', 'ND']:
            exempt_ids = [
                self.env.ref('l10n_cl_fe.dc_y_f_dtn').id,
                self.env.ref('l10n_cl_fe.dc_y_f_dte').id]
            for document_class in document_classes:
                if document_class.sii_document_class_id.id in exempt_ids:
                    document_class_id = document_class.id
                    break
                else:
                    document_class_id = document_classes.ids[0]
        else:
            document_class_id = document_classes.ids[0]
        return document_class_id

    @api.onchange('company_id')
    def _set_available_issuer_turns(self):
        for rec in self:
            if rec.company_id:
                available_turn_ids = rec.company_id.company_activities_ids
                for turn in available_turn_ids:
                    rec.turn_issuer = turn

    @api.onchange('currency_id', 'move_lines', 'move_reason')
    def _compute_amount(self):
        for rec in self:
            if rec.move_reason not in ['5']:
                taxes = {}
                amount_untaxed = amount_tax = 0
                if rec.move_lines:
                    for move in rec.move_lines:
                        amount_untaxed += move.subtotal
                        if move.move_line_tax_ids:
                            for t in move.move_line_tax_ids:
                                taxes.setdefault(t.id,[t, 0])
                                taxes[t.id][1] += move.subtotal
                if taxes:
                    for t, value in taxes.items():
                        amount_tax += value[0].compute_all(value[1], rec.currency_id, 1)['taxes'][0]['amount']
                rec.amount_tax = amount_tax
                rec.amount_untaxed = amount_untaxed
            rec.amount_total = rec.amount_untaxed + rec.amount_tax

    def set_use_document(self):
        return (self.picking_type_id and self.picking_type_id.code != 'incoming')

    amount_untaxed = fields.Monetary(
            compute='_compute_amount',
            digits_compute=dp.get_precision('Account'),
            string='Untaxed Amount',
        )
    amount_tax = fields.Monetary(
            compute='_compute_amount',
            digits_compute=dp.get_precision('Account'),
            string='Taxes',
        )
    amount_total = fields.Monetary(
            compute='_compute_amount',
            digits_compute=dp.get_precision('Account'),
            string='Total',
        )
    currency_id = fields.Many2one(
            'res.currency',
            string='Currency',
            required=True,
            states={'draft': [('readonly', False)]},
            default=lambda self: self.env.user.company_id.currency_id,
            track_visibility='always',
        )
    sii_batch_number = fields.Integer(
            copy=False,
            string='Batch Number',
            readonly=True,
            help='Batch number for processing multiple invoices together',
        )
    turn_issuer = fields.Many2one(
            'partner.activities',
            string='Giro Emisor',
            store=True,
            invisible=True,
            readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]},
        )
    partner_turn = fields.Many2one(
            'partner.activities',
            string='Giro',
            store=True,
            readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]},
        )
    activity_description = fields.Many2one(
            'sii.activity.description',
            string='Giro',
            related="partner_id.commercial_partner_id.activity_description",
            readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]},
        )
    sii_document_number = fields.Char(
            string='Document Number',
            copy=False,
            readonly=True,
        )
    responsability_id = fields.Many2one(
            'sii.responsability',
            string='Responsability',
            related='partner_id.commercial_partner_id.responsability_id',
            store=True,
        )
    next_number = fields.Integer(
            related='picking_type_id.sequence_id.number_next_actual',
            string='Next Document Number',
            readonly=True,
        )
    use_documents = fields.Boolean(
            string='Use Documents?',
            default=set_use_document,
        )
    reference =fields.One2many(
            'stock.picking.referencias',
            'stock_picking_id',
            readonly=False,
            states={'done':[('readonly',True)]},
        )
    transport_type = fields.Selection(
            [
                ('2','Despacho por cuenta de empresa'),
                ('1','Despacho por cuenta del cliente'),
                ('3','Despacho Externo'),
                ('0','Sin Definir')
            ],
            string="Tipo de Despacho",
            default="2",
            readonly=False, states={'done':[('readonly',True)]},
        )
    move_reason = fields.Selection(
            [
                    ('1','Operación constituye venta'),
                    ('2','Ventas por efectuar'),
                    ('3','Consignaciones'),
                    ('4','Entrega Gratuita'),
                    ('5','Traslados Internos'),
                    ('6','Otros traslados no venta'),
                    ('7','Guía de Devolución'),
                    ('8','Traslado para exportación'),
                    ('9','Ventas para exportación')
            ],
            string='Razón del traslado',
            default="1",
            readonly=False, states={'done':[('readonly',True)]},
        )
    vehicle = fields.Many2one(
            'fleet.vehicle',
            string="Vehículo",
            readonly=False,
            states={'done':[('readonly',True)]},
        )
    chofer= fields.Many2one(
            'res.partner',
            string="Chofer",
            readonly=False,
            states={'done':[('readonly',True)]},
        )
    patente = fields.Char(
            string="Patente",
            readonly=False,
            states={'done':[('readonly',True)]},
        )
    contact_id = fields.Many2one(
            'res.partner',
            string="Contacto",
            readonly=False,
            states={'done':[('readonly',True)]},
        )
    invoiced = fields.Boolean(
            string='Invoiced?',
            readonly=True,
    )

    @api.onchange('picking_type_id')
    def onchange_picking_type(self,):
        if self.picking_type_id:
            self.use_documents = self.picking_type_id.code not in [ "incoming" ]

    @api.onchange('company_id')
    def _refreshData(self):
        if self.move_lines:
            for m in self.move_lines:
                m.company_id = self.company_id.id

    @api.onchange('vehicle')
    def _setChofer(self):
        self.chofer = self.vehicle.driver_id
        self.patente = self.vehicle.license_plate

class StockLocation(models.Model):
    _inherit = 'stock.location'

    sii_document_class_id = fields.Many2one(
            'sii.document_class',
            string='Document Type',
            required=True,
        )
    sequence_id = fields.Many2one(
            'ir.sequence',
            string='Entry Sequence',
            required=False,
            help="""This field contains the information related to the numbering \
            of the documents entries of this document type.""",
        )
    sii_code = fields.Char(
            string="Código de Sucursal SII",
        )

class Referencias(models.Model):
    _name = 'stock.picking.referencias'

    origen = fields.Char(
            string="Origin",
        )
    sii_referencia_TpoDocRef =  fields.Many2one(
            'sii.document_class',
            string="SII Reference Document Type",
        )
    date = fields.Date(
            string="Fecha de la referencia",
        )
    stock_picking_id = fields.Many2one(
            'stock.picking',
            ondelete='cascade',
            index=True,
            copy=False,
            string="Documento",
        )

class StockMove(models.Model):
    _inherit = 'stock.move'

    @api.model
    def create(self,vals):
        if 'picking_id' in vals:
            picking = self.env['stock.picking'].browse(vals['picking_id'])
            if picking and picking.company_id:
                vals['company_id'] = picking.company_id.id
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
            if rec.price_unit <= 0:
                rec.price_unit = rec.product_id.lst_price
                rec.move_line_tax_ids = rec.product_id.taxes_id # @TODO mejorar asignación
            if not rec.name:
                rec.name = rec.product_id.name

    @api.onchange('name','product_id','move_line_tax_ids','product_uom_qty', 'price_unit', 'quantity_done')
    def _compute_amount(self):
        for rec in self:
            price = rec.price_unit * (1 - (rec.discount or 0.0) / 100.0)
            qty = rec.quantity_done
            if qty <= 0:
                qty = rec.product_uom_qty
            rec.subtotal = qty * price

    name = fields.Char(
            string="Nombre",
        )
    subtotal = fields.Monetary(
            compute='_compute_amount',
            string='Subtotal',
        )
    price_unit = fields.Monetary(
            string='Price',
        )
    price_untaxed = fields.Monetary(
            compute='_sale_prices',
            string='Price Untaxed',
        )
    move_line_tax_ids = fields.Many2many(
            'account.tax',
            'move_line_tax_ids',
            'move_line_id',
            'tax_id',
            string='Taxes',
            domain=[('type_tax_use','!=','none'), '|', ('active', '=', False), ('active', '=', True)],
            oldname='invoice_line_tax_id',
        )
    discount = fields.Monetary(
            digits_compute=dp.get_precision('Discount'),
            string='Discount (%)',
        )
    currency_id = fields.Many2one(
            'res.currency',
            string='Currency',
            required=True,
            readonly=True,
            states={'draft': [('readonly', False)]},
            default=lambda self: self.env.user.company_id.currency_id,
            track_visibility='always',
        )

class MQ(models.Model):
    _inherit = 'stock.quant'

    description = fields.Char(
            string="Description",
        )
    price_unit = fields.Monetary(
            digits_compute=dp.get_precision('Product Price'),
            string='Price',
        )
    currency_id = fields.Many2one('res.currency',
            string='Currency',
            required=True,
            readonly=True,
            default=lambda self: self.env.user.company_id.currency_id,
            track_visibility='always'
        )
    quant_line_tax_ids = fields.Many2many(
            'account.tax',
            'quant_line_tax_ids',
            'quant_line_id',
            'tax_id',
            string='Taxes',
            domain=[
                ('type_tax_use','!=','none'),
                '|',
                ('active', '=', False),
                ('active', '=', True)
            ],
            oldname='invoice_line_tax_id',
        )

#@TODO MODIFICAR según nueva estructura, este metodo está obsoleto
    def _quant_create(self, cr, uid, qty, move, lot_id=False, owner_id=False, src_package_id=False, dest_package_id=False,
                      force_location_from=False, force_location_to=False, context=None):
        '''Create a quant in the destination location and create a negative quant in the source location if it's an internal location.
        '''
        if context is None:
            context = {}
        price_unit = self.pool.get('stock.move').get_price_unit(cr, uid, move, context=context)
        location = force_location_to or move.location_dest_id
        rounding = move.product_id.uom_id.rounding
        vals = {
            'product_id': move.product_id.id,
            'location_id': location.id,
            'qty': float_round(qty, precision_rounding=rounding),
            'cost': price_unit,
            'history_ids': [(4, move.id)],
            'in_date': datetime.now().strftime(DEFAULT_SERVER_DATETIME_FORMAT),
            'company_id': move.company_id.id,
            'lot_id': lot_id,
            'owner_id': owner_id,
            'package_id': dest_package_id,
            'description': move.name,
            'price_unit': move.price_unit,
            'currency_id': move.currency_id.id,
            'quant_line_tax_ids': [( 6, 0, move.move_line_tax_ids.ids )],
        }
        if move.location_id.usage == 'internal':
            #if we were trying to move something from an internal location and reach here (quant creation),
            #it means that a negative quant has to be created as well.
            negative_vals = vals.copy()
            negative_vals['location_id'] = force_location_from and force_location_from.id or move.location_id.id
            negative_vals['qty'] = float_round(-qty, precision_rounding=rounding)
            negative_vals['cost'] = price_unit
            negative_vals['negative_move_id'] = move.id
            negative_vals['package_id'] = src_package_id
            negative_quant_id = self.create(cr, SUPERUSER_ID, negative_vals, context=context)
            vals.update({'propagated_from_id': negative_quant_id})

        picking_type = move.picking_id and move.picking_id.picking_type_id or False
        if lot_id and move.product_id.tracking == 'serial' and (not picking_type or (picking_type.use_create_lots or picking_type.use_existing_lots)):
            if qty != 1.0:
                raise UserError(_('You should only receive by the piece with the same serial number'))

        #create the quant as superuser, because we want to restrict the creation of quant manually: we should always use this method to create quants
        quant_id = self.create(cr, SUPERUSER_ID, vals, context=context)
        return self.browse(cr, uid, quant_id, context=context)
