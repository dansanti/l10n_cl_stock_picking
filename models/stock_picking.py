# -*- coding: utf-8 -*-
from datetime import date, datetime
from odoo import osv, models, fields, api, _, SUPERUSER_ID
from odoo import fields
from odoo.exceptions import except_orm, UserError
import odoo.addons.decimal_precision as dp
from odoo.tools.float_utils import float_compare, float_round
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, DEFAULT_SERVER_DATE_FORMAT
from collections import namedtuple
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

    @api.onchange('pack_operation_product_ids', 'currency_id', 'company_id')
    def _compute_amount(self):
        for rec in self:
            taxes = {}
            amount_untaxed = amount_tax = 0
            if rec.pack_operation_product_ids and rec.state not in ['draft']:
                for operation in rec.pack_operation_product_ids:
                    amount_untaxed += operation.subtotal
                    if operation.operation_line_tax_ids:
                        for t in operation.operation_line_tax_ids:
                            taxes.setdefault(t.id,[t, 0])
                            taxes[t.id][1] += operation.subtotal
            elif rec.move_lines:
                for move in rec.move_lines:
                    rec.amount_untaxed += move.subtotal
                    if move.move_line_tax_ids:
                        for t in move.move_line_tax_ids:
                            taxes.setdefault(t.id,[t, 0])
                            taxes[t.id][1] += move.subtotal
            for t, value in taxes.iteritems():
                amount_tax += value[0].compute_all(value[1], rec.currency_id, 1)['taxes'][0]['amount']
            rec.amount_untaxed = amount_untaxed
            rec.amount_tax = amount_tax
            rec.amount_total = amount_untaxed + rec.amount_tax

    def set_use_document(self):
        return (self.picking_type_id and self.picking_type_id.code != 'incoming')

    amount_untaxed = fields.Monetary(compute='_compute_amount',
        digits=dp.get_precision('Account'),
        string='Untaxed Amount')
    amount_tax = fields.Monetary(compute='_compute_amount',
        digits=dp.get_precision('Account'),
        string='Taxes')
    amount_total = fields.Monetary(compute='_compute_amount',
        digits=dp.get_precision('Account'),
        string='Total')
    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')
    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together',
    )
    turn_issuer = fields.Many2one(
        'partner.activities',
        'Giro Emisor',
        store=True,
        invisible=True,
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})
    activity_description = fields.Many2one(
        'sii.activity.description',
        'Giro',
        related="partner_id.commercial_partner_id.activity_description",
        readonly=True, states={'assigned':[('readonly',False)],'draft':[('readonly',False)]})
    sii_document_number = fields.Char(
        string='Document Number',
        copy=False,
        readonly=True,)
    responsability_id = fields.Many2one(
        'sii.responsability',
        string='Responsability',
        related='partner_id.commercial_partner_id.responsability_id',
        store=True,
        )
    next_number = fields.Integer(
        related='picking_type_id.sequence_id.number_next_actual',
        string='Next Document Number',
        readonly=True)
    use_documents = fields.Boolean(
        string='Use Documents?',
        default=set_use_document,
        )
    reference =fields.One2many('stock.picking.referencias',
       'stock_picking_id',
       readonly=False, states={'done':[('readonly',True)]})
    transport_type = fields.Selection(
        [('2','Despacho por cuenta de empresa'),
         ('1','Despacho por cuenta del cliente'),
         ('3','Despacho Externo'),
         ('0','Sin Definir')
        ],
        string="Tipo de Despacho",
        default="2",
        readonly=False, states={'done':[('readonly',True)]})
    move_reason = fields.Selection(
        [('1','Operación constituye venta'),
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
        readonly=False, states={'done':[('readonly',True)]})
    vehicle = fields.Many2one('fleet.vehicle',
      string="Vehículo",
      readonly=False,
      states={'done':[('readonly',True)]})
    chofer= fields.Many2one('res.partner',
        string="Chofer",
        readonly=False,
        states={'done':[('readonly',True)]})
    patente = fields.Char(string="Patente",
        readonly=False,
        states={'done':[('readonly',True)]})
    contact_id = fields.Many2one('res.partner',
        string="Contacto",
        readonly=False,
        states={'done':[('readonly',True)]})
    invoiced = fields.Boolean(
        string='Invoiced?',
        readonly=True,
    )

    def onchange_picking_type(self, cr, uid, ids, picking_type_id, partner_id, context=None):
        res = super(StockPicking, self).onchange_picking_type(cr, uid, ids, picking_type_id, partner_id, context=context)
        if picking_type_id:
            picking_type = self.pool['stock.picking.type'].browse(cr, uid, picking_type_id, context=context)
            res['value'].update({'use_documents': (picking_type.code not in [ "incoming" ])})
        return res

    @api.onchange('company_id')
    def _refreshData(self):
        if self.move_lines:
            for m in self.move_lines:
                m.company_id = self.company_id.id

    @api.onchange('vehicle')
    def _setChofer(self):
        self.chofer = self.vehicle.driver_id
        self.patente = self.vehicle.license_plate

    @api.onchange('pack_operation_product_ids')
    def _setValues(self):
        for rec in self:
            if rec.pack_operation_product_ids:
                for m in rec.pack_operation_product_ids:
                    for l in rec.move_lines_related:
                        if l.product_id.id == m.product_id.id:
                            m.price_unit = l.price_unit_sales
                            m.discount = l.discount
                            m.operation_line_tax_ids = l.move_line_tax_ids
                if not m.price_unit > 0 or not m.name:
                    m.price_unit = m.product_id.lst_price
                    if not m.name:
                    	m.name = m.product_id.name
                    m.operation_line_tax_ids = m.product_id.taxes_id # @TODO mejorar asignación

    def _prepare_pack_ops(self, quants, forced_qties):
        """ Prepare pack_operations, returns a list of dict to give at create """
        # TDE CLEANME: oh dear ...
        valid_quants = quants.filtered(lambda quant: quant.qty > 0)
        _Mapping = namedtuple('Mapping', ('product', 'package', 'owner', 'location', 'location_dst_id'))

        all_products = valid_quants.mapped('product_id') | self.env['product.product'].browse(p['key'].id for p in forced_qties) | self.move_lines.mapped('product_id')
        computed_putaway_locations = dict(
            (product, self.location_dest_id.get_putaway_strategy(product) or self.location_dest_id.id) for product in all_products)

        product_to_uom = dict((product.id, product.uom_id) for product in all_products)
        picking_moves = self.move_lines.filtered(lambda move: move.state not in ('done', 'cancel'))
        for move in picking_moves:
            # If we encounter an UoM that is smaller than the default UoM or the one already chosen, use the new one instead.
            if move.product_uom != product_to_uom[move.product_id.id] and move.product_uom.factor > product_to_uom[move.product_id.id].factor:
                product_to_uom[move.product_id.id] = move.product_uom
        if len(picking_moves.mapped('location_id')) > 1:
            raise UserError(_('The source location must be the same for all the moves of the picking.'))
        if len(picking_moves.mapped('location_dest_id')) > 1:
            raise UserError(_('The destination location must be the same for all the moves of the picking.'))

        pack_operation_values = []
        # find the packages we can move as a whole, create pack operations and mark related quants as done
        top_lvl_packages = valid_quants._get_top_level_packages(computed_putaway_locations)
        for pack in top_lvl_packages:
            pack_quants = pack.get_content()
            pack_operation_values.append({
                'picking_id': self.id,
                'package_id': pack.id,
                'product_qty': 1.0,
                'location_id': pack.location_id.id,
                'location_dest_id': computed_putaway_locations[pack_quants[0].product_id],
                'owner_id': pack.owner_id.id,
            })
            valid_quants -= pack_quants

        # Go through all remaining reserved quants and group by product, package, owner, source location and dest location
        # Lots will go into pack operation lot object
        qtys_grouped = []
        lots_grouped = {}
        for quant in valid_quants:
            key = _Mapping(quant.product_id, quant.package_id, quant.owner_id, quant.location_id, computed_putaway_locations[quant.product_id])
            form_name = '[' + quant.product_id.default_code +'] ' + quant.product_id.name if quant.product_id.default_code else quant.product_id.name
            price_unit = quant.product_id.lst_price if quant.price_unit == 0 else quant.price_unit
            qtys_grouped.extend([{'key': key,'value': quant.qty, 'name': form_name,'price_unit': price_unit}])
            if quant.product_id.tracking != 'none' and quant.lot_id:
                lots_grouped.setdefault(key, dict()).setdefault(quant.lot_id.id, 0.0)
                lots_grouped[key][quant.lot_id.id] += quant.qty
        # Do the same for the forced quantities (in cases of force_assign or incomming shipment for example)
        for it in forced_qties:
            product = it['key']
            qty = it['value']
            if qty <= 0.0:
                continue
            key = _Mapping(product, self.env['stock.quant.package'], self.owner_id, self.location_id, computed_putaway_locations[product])
            qtys_grouped.extend([{'key':key,'value': qty, 'name' : it['name'] ,'price_unit': it['price_unit']}])

        # Create the necessary operations for the grouped quants and remaining qtys
        Uom = self.env['product.uom']
        product_id_to_vals = {}  # use it to create operations using the same order as the picking stock moves
        for it in qtys_grouped:
            mapping = it['key']
            qty = it['value']
            uom = product_to_uom[mapping.product.id]
            val_dict = {
                'picking_id': self.id,
                'product_qty': mapping.product.uom_id._compute_quantity(qty, uom),
                'product_id': mapping.product.id,
                'package_id': mapping.package.id,
                'owner_id': mapping.owner.id,
                'location_id': mapping.location.id,
                'location_dest_id': mapping.location_dst_id,
                'product_uom_id': uom.id,
                'pack_lot_ids': [
                    (0, 0, {'lot_id': lot, 'qty': 0.0, 'qty_todo': lots_grouped[mapping][lot]})
                    for lot in lots_grouped.get(mapping, {}).keys()],
            }
            if 'name' in it:
                val_dict['name'] = it['name']
            if 'price_unit' in it:
                val_dict['price_unit'] = it['price_unit']
            product_id_to_vals.setdefault((mapping.product.id, it['name']), list()).append(val_dict)

        for move in self.move_lines.filtered(lambda move: move.state not in ('done', 'cancel')):
            values = product_id_to_vals.pop((move.product_id.id, move.name ), [])
            pack_operation_values += values
        return pack_operation_values

    @api.multi
    def do_prepare_partial(self):
        # TDE CLEANME: oh dear ...
        PackOperation = self.env['stock.pack.operation']

        # get list of existing operations and delete them
        existing_packages = PackOperation.search([('picking_id', 'in', self.ids)])  # TDE FIXME: o2m / m2o ?
        if existing_packages:
            existing_packages.unlink()
        for picking in self:
            forced_qties = []  # Quantity remaining after calculating reserved quants
            picking_quants = self.env['stock.quant']
            # Calculate packages, reserved quants, qtys of this picking's moves
            for move in picking.move_lines:
                if move.state not in ('assigned', 'confirmed', 'waiting'):
                    continue
                move_quants = move.reserved_quant_ids
                for mq in move_quants:
                    mq.sudo().write({'price_unit': move.price_unit_sales, 'name': move.name})
                picking_quants += move_quants
                forced_qty = 0.0
                if move.state == 'assigned':
                    qty = move.product_uom._compute_quantity(move.product_uom_qty, move.product_id.uom_id, round=False)
                    forced_qty = qty - sum([x.qty for x in move_quants])
                #if we used force_assign() on the move, or if the move is incoming, forced_qty > 0
                if float_compare(forced_qty, 0, precision_rounding=move.product_id.uom_id.rounding) > 0:
                    forced_qties.extend([{'key': move.product_id, 'value': forced_qty, 'name' : move.name ,'price_unit': move.price_unit_sales}])
            for vals in picking._prepare_pack_ops(picking_quants, forced_qties):
                vals['fresh_record'] = False
                PackOperation.create(vals)
        # recompute the remaining quantities all at once
        self.do_recompute_remaining_quantities()
        self.write({'recompute_pack_op': False})


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

    origen = fields.Char(string="Origin")
    sii_referencia_TpoDocRef =  fields.Many2one('sii.document_class',
        string="SII Reference Document Type")
    date = fields.Date(string="Fecha de la referencia")
    stock_picking_id = fields.Many2one('stock.picking', ondelete='cascade',index=True,copy=False,string="Documento")

class StockPackOperation(models.Model):
    _inherit = "stock.pack.operation"

    def create(self, vals):
        picking_id = self.env['stock.picking'].browse(vals['picking_id'])
        for o in picking_id.move_lines:
            if vals['product_id'] == o.product_id.id and o.name == vals['name']:
                vals['subtotal'] = o.subtotal
                vals['discount'] = o.discount
                vals['operation_line_tax_ids'] = [(6, 0, o.move_line_tax_ids.ids)]
        super(StockPackOperation,self).create(vals)

    @api.depends('picking_id.move_lines_related')
    @api.onchange('name', 'qty_done')
    def _setValues(self):
        for rec in self:
            for l in rec.picking_id.move_lines_related:
                if l.product_id.id == rec.product_id.id and l.name == rec.name:
                    rec.price_unit = l.price_unit_sales
                    rec.discount = l.discount
                    rec.operation_line_tax_ids = l.move_line_tax_ids
            if not rec.price_unit > 0 or not rec.name:
            	if not rec.name:
            		rec.name = rec.product_id.name
                rec.price_unit = rec.product_id.lst_price
                rec.operation_line_tax_ids = rec.product_id.taxes_id # @TODO mejorar asignación

    name = fields.Char(string="Nombre")
    subtotal = fields.Monetary(
        compute='_compute_amount',
        digits=dp.get_precision('Account'),
        string='Subtotal')
    price_unit = fields.Monetary(
        digits=dp.get_precision('Product Price'),
        string='Price',
    )
    price_untaxed = fields.Monetary(
        digits=dp.get_precision('Product Price'),
        string='Price Untaxed',
    )
    operation_line_tax_ids = fields.Many2many(
        'account.tax',
        'operation_line_tax',
        'operation_line_id',
        'tax_id',
        string='Taxes',
        domain=[
            ('type_tax_use','!=','none'),
            '|',
            ('active', '=', False),
            ('active', '=', True)
        ],
        oldname='invoice_line_tax_id'
    )
    discount = fields.Monetary(
        digits=dp.get_precision('Discount'),
        string='Discount (%)',
    )
    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        required=True,
        readonly=True,
        states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')

    @api.onchange('price_unit','qty_done','product_id','operation_line_tax_ids')
    def _compute_amount(self):
        for rec in self:
            rec.subtotal = rec.qty_done * ( rec.price_unit * (1 - rec.discount/100.0))

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
                    if ref.sii_referencia_TpoDocRef.sii_code in [34, 33]:# factura venta
                        inv = self.env['account.invoice'].search([('sii_document_number','=',ref.origen)])
                        for l in inv.invoice_lines:
                            if l.product_id.id == rec.product_id.id:
                                rec.price_unit_sales = l.price_unit
                                rec.subtotal = l.subtotal
                                rec.discount = l.discount
                                rec.move_line_tax_ids = l.invoice_line_tax_ids
            if not rec.price_unit_sales > 0 or not rec.name:
                rec.price_unit_sales = rec.product_id.lst_price
                if not rec.name:
                	rec.name = rec.product_id.name
                rec.move_line_tax_ids = rec.product_id.taxes_id # @TODO mejorar asignación

    @api.onchange('name','product_id','move_line_tax_ids','product_uom_qty')
    def _compute_amount(self):
        for rec in self:
            price = rec.price_unit_sales * (1 - (rec.discount or 0.0) / 100.0)
            rec.subtotal = rec.product_uom_qty * price

    name = fields.Char(string="Nombre")

    subtotal = fields.Monetary(
        compute='_compute_amount', digits=dp.get_precision('Product Price'),
        string='Subtotal')

    price_unit_sales = fields.Monetary(
        digits=dp.get_precision('Product Price'),
        string='Price',
    )
    price_untaxed = fields.Monetary(
        compute='_sale_prices',
        digits=dp.get_precision('Product Price'),
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
        digits=dp.get_precision('Discount'),
        string='Discount (%)',
    )
    currency_id = fields.Many2one('res.currency', string='Currency',
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
        digits=dp.get_precision('Product Price'),
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

    def _quant_create_from_move(self, qty, move, lot_id=False, owner_id=False,
                                src_package_id=False, dest_package_id=False,
                                force_location_from=False, force_location_to=False):
        '''Create a quant in the destination location and create a negative
        quant in the source location if it's an internal location. '''
        price_unit = move.get_price_unit()
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
            'price_unit': move.price_unit_sales,
            'currency_id': move.currency_id.id,
            'quant_line_tax_ids': [( 6, 0, move.move_line_tax_ids.ids )],
        }
        if move.location_id.usage == 'internal':
            # if we were trying to move something from an internal location and reach here (quant creation),
            # it means that a negative quant has to be created as well.
            negative_vals = vals.copy()
            negative_vals['location_id'] = force_location_from and force_location_from.id or move.location_id.id
            negative_vals['qty'] = float_round(-qty, precision_rounding=rounding)
            negative_vals['cost'] = price_unit
            negative_vals['negative_move_id'] = move.id
            negative_vals['package_id'] = src_package_id
            negative_quant_id = self.sudo().create(negative_vals)
            vals.update({'propagated_from_id': negative_quant_id.id})

        picking_type = move.picking_id and move.picking_id.picking_type_id or False
        if lot_id and move.product_id.tracking == 'serial' and (not picking_type or (picking_type.use_create_lots or picking_type.use_existing_lots)):
            if qty != 1.0:
                raise UserError(_('You should only receive by the piece with the same serial number'))

        # create the quant as superuser, because we want to restrict the creation of quant manually: we should always use this method to create quants
        return self.sudo().create(vals)
