from odoo import models, http
from odoo.addons.web.controllers.main import serialize_exception
from odoo.addons.web.controllers.downloader import document

class Binary(http.Controller):

    @http.route(["/download/xml/guia/<model('stock.picking'):document_id>"], type='http', auth='user')
    @serialize_exception
    def download_document(self, document_id, **post):
        filename = ('%s.xml' % document_id.document_number).replace(' ','_')
        filecontent = document_id.sii_xml_request
        return self.document(filename, filecontent)

    @http.route(["/download/xml/libro_guia/<model('stock.picking.book'):document_id>"], type='http', auth='user')
    @serialize_exception
    def download_document(self, document_id, **post):
        filename = ('%s.xml' % document_id.name).replace(' ','_')
        filecontent = document_id.sii_xml_request
        return self.document(filename, filecontent)
