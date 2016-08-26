# -*- coding: utf-8 -*-


from openerp import fields, models, api, _
from openerp.exceptions import Warning
from openerp.exceptions import UserError
from datetime import datetime, timedelta
import logging
from lxml import etree
from lxml.etree import Element, SubElement
from lxml import objectify
from lxml.etree import XMLSyntaxError
from openerp import SUPERUSER_ID

import xml.dom.minidom
import pytz


import socket
import collections

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

# ejemplo de suds
import traceback as tb
import suds.metrics as metrics
#from tests import *
#from suds import WebFault
#from suds.client import Client
# from suds.sax.text import Raw
# import suds.client as sudscl

try:
    from suds.client import Client
except:
    pass
# from suds.transport.https import WindowsHttpAuthenticated
# from suds.cache import ObjectCache

# ejemplo de suds

# intento con urllib3
try:
    import urllib3
except:
    pass

# from urllib3 import HTTPConnectionPool
#urllib3.disable_warnings()
pool = urllib3.PoolManager()
# ca_certs = "/etc/ssl/certs/ca-certificates.crt"
# pool = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)
import textwrap

# from inspect import currentframe, getframeinfo
# estas 2 lineas son para imprimir el numero de linea del script
# (solo para debug)

_logger = logging.getLogger(__name__)

try:
    import xmltodict
except ImportError:
    _logger.info('Cannot import xmltodict library')

try:
    import dicttoxml
except ImportError:
    _logger.info('Cannot import dicttoxml library')

try:
    from elaphe import barcode
except ImportError:
    _logger.info('Cannot import elaphe library')

try:
    import M2Crypto
except ImportError:
    _logger.info('Cannot import M2Crypto library')

try:
    import base64
except ImportError:
    _logger.info('Cannot import base64 library')

try:
    import hashlib
except ImportError:
    _logger.info('Cannot import hashlib library')

try:
    import cchardet
except ImportError:
    _logger.info('Cannot import cchardet library')

try:
    from SOAPpy import SOAPProxy
except ImportError:
    _logger.info('Cannot import SOOAPpy')

try:
    from signxml import xmldsig, methods
except ImportError:
    _logger.info('Cannot import signxml')

# timbre patrón. Permite parsear y formar el
# ordered-dict patrón corespondiente al documento
timbre  = """<TED version="1.0"><DD><RE>99999999-9</RE><TD>11</TD><F>1</F>\
<FE>2000-01-01</FE><RR>99999999-9</RR><RSR>\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</RSR><MNT>10000</MNT><IT1>IIIIIII\
</IT1><CAF version="1.0"><DA><RE>99999999-9</RE><RS>YYYYYYYYYYYYYYY</RS>\
<TD>10</TD><RNG><D>1</D><H>1000</H></RNG><FA>2000-01-01</FA><RSAPK><M>\
DJKFFDJKJKDJFKDJFKDJFKDJKDnbUNTAi2IaDdtAndm2p5udoqFiw==</M><E>Aw==</E></RSAPK>\
<IDK>300</IDK></DA><FRMA algoritmo="SHA1withRSA">\
J1u5/1VbPF6ASXkKoMOF0Bb9EYGVzQ1AMawDNOy0xSuAMpkyQe3yoGFthdKVK4JaypQ/F8\
afeqWjiRVMvV4+s4Q==</FRMA></CAF><TSTED>2014-04-24T12:02:20</TSTED></DD>\
<FRMT algoritmo="SHA1withRSA">jiuOQHXXcuwdpj8c510EZrCCw+pfTVGTT7obWm/\
fHlAa7j08Xff95Yb2zg31sJt6lMjSKdOK+PQp25clZuECig==</FRMT></TED>"""
result = xmltodict.parse(timbre)

server_url = {'SIIHOMO':'https://maullin.sii.cl/DTEWS/','SII':'https://palena.sii.cl/DTEWS/'}

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

# hardcodeamos este valor por ahora
import os
xsdpath = os.path.dirname(os.path.realpath(__file__)).replace('/models','/static/xsd/')

connection_status = {
    '0': 'Upload OK',
    '1': 'El Sender no tiene permiso para enviar',
    '2': 'Error en tamaño del archivo (muy grande o muy chico)',
    '3': 'Archivo cortado (tamaño <> al parámetro size)',
    '5': 'No está autenticado',
    '6': 'Empresa no autorizada a enviar archivos',
    '7': 'Esquema Invalido',
    '8': 'Firma del Documento',
    '9': 'Sistema Bloqueado',
    'Otro': 'Error Interno.',
}

class stock_picking(models.Model):
    _inherit = "stock.picking"

    def split_cert(self, cert):
        # certp = cert.replace('\n', '')
        certf, j = '', 0
        for i in range(0, 29):
            certf += cert[76 * i:76 * (i + 1)] + '\n'
        return certf

    def create_template_envio(self, RutEmisor, RutReceptor, FchResol, NroResol,
                              TmstFirmaEnv, EnvioDTE,signature_d,SubTotDTE):
        xml = '''<SetDTE ID="SetDoc">
<Caratula version="1.0">
<RutEmisor>{0}</RutEmisor>
<RutEnvia>{1}</RutEnvia>
<RutReceptor>{2}</RutReceptor>
<FchResol>{3}</FchResol>
<NroResol>{4}</NroResol>
<TmstFirmaEnv>{5}</TmstFirmaEnv>
{6}</Caratula>
{7}
</SetDTE>
'''.format(RutEmisor, signature_d['subject_serial_number'], RutReceptor,
           FchResol, NroResol, TmstFirmaEnv, SubTotDTE, EnvioDTE)
        return xml

    def time_stamp(self, formato='%Y-%m-%dT%H:%M:%S'):
        tz = pytz.timezone('America/Santiago')
        return datetime.now(tz).strftime(formato)

    '''
    Funcion auxiliar para conversion de codificacion de strings
     proyecto experimentos_dte
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2014-12-01
    '''
    def convert_encoding(self, data, new_coding = 'UTF-8'):
        encoding = cchardet.detect(data)['encoding']
        if new_coding.upper() != encoding.upper():
            data = data.decode(encoding, data).encode(new_coding)
        return data

    '''
    Funcion para validar los xml generados contra el esquema que le corresponda
    segun el tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def xml_validator(self, some_xml_string, validacion='doc'):
        if 1==1:
            validacion_type = {
                'doc': 'DTE_v10.xsd',
                'env': 'EnvioDTE_v10.xsd',
                'sig': 'xmldsignature_v10.xsd'
            }
            xsd_file = xsdpath+validacion_type[validacion]
            try:
                schema = etree.XMLSchema(file=xsd_file)
                parser = objectify.makeparser(schema=schema)
                objectify.fromstring(some_xml_string, parser)
                return True
            except XMLSyntaxError as e:
                raise Warning(_('XML Malformed Error %s') % e.args)

    '''
    Funcion usada en autenticacion en SII
    Obtencion de la semilla desde el SII.
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-04-01
    '''
    def get_seed(self, company_id):
        #En caso de que haya un problema con la validación de certificado del sii ( por una mala implementación de ellos)
        #esto omite la validacion
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context
        url = server_url[company_id.dte_service_provider] + 'CrSeed.jws?WSDL'
        ns = 'urn:'+server_url[company_id.dte_service_provider] + 'CrSeed.jws'
        _server = SOAPProxy(url, ns)
        root = etree.fromstring(_server.getSeed())
        semilla = root[0][0].text
        return semilla

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para realizar el envio del token
    Previo a realizar su firma
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_seed(self, seed):
        xml = u'''<getToken>
<item>
<Semilla>{}</Semilla>
</item>
</getToken>
'''.format(seed)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para envolver el DTE
    Previo a realizar su firma (1)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_doc(self, doc):
        xml = '''<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
{}</DTE>'''.format(doc)
        return xml

    def create_template_env(self, doc):
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<EnvioDTE xmlns="http://www.sii.cl/SiiDte" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="http://www.sii.cl/SiiDte EnvioDTE_v10.xsd" \
version="1.0">
{}</EnvioDTE>'''.format(doc)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Insercion del nodo de firma (1ra) dentro del DTE
    Una vez firmado.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_doc1(self, doc, sign):
        xml = doc.replace('</DTE>', '') + sign + '</DTE>'
        return xml

    '''
    Funcion usada en autenticacion en SII
    Insercion del nodo de firma (2da) dentro del DTE
    Una vez firmado.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_env1(self, doc, sign):
        xml = doc.replace('</EnvioDTE>', '') + sign + '</EnvioDTE>'
        return xml

    '''
    Funcion usada en autenticacion en SII
    Firma de la semilla utilizando biblioteca signxml
    De autoria de Andrei Kislyuk https://github.com/kislyuk/signxml
    (en este caso particular esta probada la efectividad de la libreria)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def sign_seed(self, message, privkey, cert):
        doc = etree.fromstring(message)
        signed_node = xmldsig(
            doc, digest_algorithm=u'sha1').sign(
            method=methods.enveloped, algorithm=u'rsa-sha1',
            key=privkey.encode('ascii'),
            cert=cert)
        msg = etree.tostring(
            signed_node, pretty_print=True).replace('ds:', '')
        return msg

    '''
    Funcion usada en autenticacion en SII
    Obtencion del token a partir del envio de la semilla firmada
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_token(self, seed_file,company_id):
        url = server_url[company_id.dte_service_provider] + 'GetTokenFromSeed.jws?WSDL'
        ns = 'urn:'+ server_url[company_id.dte_service_provider] +'GetTokenFromSeed.jws'
        _server = SOAPProxy(url, ns)
        tree = etree.fromstring(seed_file)
        ss = etree.tostring(tree, pretty_print=True, encoding='iso-8859-1')
        respuesta = etree.fromstring(_server.getToken(ss))
        token = respuesta[0][0].text
        return token

    def ensure_str(self,x, encoding="utf-8", none_ok=False):
        if none_ok is True and x is None:
            return x
        if not isinstance(x, str):
            x = x.decode(encoding)
        return x

    def long_to_bytes(self, n, blocksize=0):
        """long_to_bytes(n:long, blocksize:int) : string
        Convert a long integer to a byte string.
        If optional blocksize is given and greater than zero, pad the front of the
        byte string with binary zeros so that the length is a multiple of
        blocksize.
        """
        # after much testing, this algorithm was deemed to be the fastest
        s = b''
        n = long(n)  # noqa
        import struct
        pack = struct.pack
        while n > 0:
            s = pack(b'>I', n & 0xffffffff) + s
            n = n >> 32
        # strip off leading zeros
        for i in range(len(s)):
            if s[i] != b'\000'[0]:
                break
        else:
            # only happens when n == 0
            s = b'\000'
            i = 0
        s = s[i:]
        # add back some pad bytes.  this could be done more efficiently w.r.t. the
        # de-padding being done above, but sigh...
        if blocksize > 0 and len(s) % blocksize:
            s = (blocksize - len(s) % blocksize) * b'\000' + s
        return s

    def sign_full_xml(self, message, privkey, cert, uri, type='doc'):
        doc = etree.fromstring(message)
        string = etree.tostring(doc[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        digest = base64.b64encode(self.digest(mess))
        reference_uri='#'+uri
        signed_info = Element("SignedInfo")
        c14n_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')
        sign_method = SubElement(signed_info, "SignatureMethod", Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1')
        reference = SubElement(signed_info, "Reference", URI=reference_uri)
        transforms = SubElement(reference, "Transforms")
        SubElement(transforms, "Transform", Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        digest_method = SubElement(reference, "DigestMethod", Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = digest
        signed_info_c14n = etree.tostring(signed_info,method="c14n",exclusive=False,with_comments=False,inclusive_ns_prefixes=None)
        if type == 'doc':
            att = 'xmlns="http://www.w3.org/2000/09/xmldsig#"'
        else:
            att = 'xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        #@TODO Find better way to add xmlns:xsi attrib
        signed_info_c14n = signed_info_c14n.replace("<SignedInfo>","<SignedInfo " + att + ">")
        sig_root = Element("Signature",attrib={'xmlns':'http://www.w3.org/2000/09/xmldsig#'})
        sig_root.append(etree.fromstring(signed_info_c14n))
        signature_value = SubElement(sig_root, "SignatureValue")
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import OpenSSL
        from OpenSSL.crypto import *
        type_ = FILETYPE_PEM
        key=OpenSSL.crypto.load_privatekey(type_,privkey.encode('ascii'))
        signature= OpenSSL.crypto.sign(key,signed_info_c14n,'sha1')
        signature_value.text =textwrap.fill(base64.b64encode(signature),64)
        key_info = SubElement(sig_root, "KeyInfo")
        key_value = SubElement(key_info, "KeyValue")
        rsa_key_value = SubElement(key_value, "RSAKeyValue")
        modulus = SubElement(rsa_key_value, "Modulus")
        key = load_pem_private_key(privkey.encode('ascii'),password=None, backend=default_backend())
        modulus.text =  textwrap.fill(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().n)),64)
        exponent = SubElement(rsa_key_value, "Exponent")
        exponent.text = self.ensure_str(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().e)))
        x509_data = SubElement(key_info, "X509Data")
        x509_certificate = SubElement(x509_data, "X509Certificate")
        x509_certificate.text = '\n'+textwrap.fill(cert,64)
        msg = etree.tostring(sig_root)
        msg = msg if self.xml_validator(msg, 'sig') else ''
        if type=='doc':
            fulldoc = self.create_template_doc1(message, msg)
            fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        if type=='env':
            fulldoc = self.create_template_env1(message,msg)
        fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        return fulldoc

    def get_digital_signature_pem(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])

            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert,
            'rut_envia': obj.subject_serial_number
            }
        return signature_data

    def get_digital_signature(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])
            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert}
        return signature_data

    '''
    Funcion usada en SII
    Toma los datos referentes a la resolución SII que autoriza a
    emitir DTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_resolution_data(self, comp_id):
        _logger.info('Entering function get_resolution_data')
        _logger.info('Service provider for this company is %s' % comp_id.dte_service_provider)
        resolution_data = {
            'dte_resolution_date': comp_id.dte_resolution_date,
            'dte_resolution_number': comp_id.dte_resolution_number}
        return resolution_data

    @api.multi
    def send_xml_file(self, envio_dte=None, file_name="envio",company_id=False):
        if not company_id.dte_service_provider:
            raise UserError(_("Not Service provider selected!"))
        if company_id.dte_service_provider in ['SII', 'SIIHOMO']:
            if 1==1:
                try:
                    signature_d = self.get_digital_signature_pem(
                        company_id)
                    seed = self.get_seed(company_id)
                    template_string = self.create_template_seed(seed)
                    seed_firmado = self.sign_seed(
                        template_string, signature_d['priv_key'],
                        signature_d['cert'])
                    token = self.get_token(seed_firmado,company_id)
                except:
                    raise Warning(connection_status[response.e])
            else:
                #except:
                # no pudo hacer el envío
                return {'sii_result': 'NoEnviado'}
            ######### fin de bloque de autenticacion ###########

            ########### inicio del bloque de envio #############
            ###
            url = 'https://palena.sii.cl'
            if company_id.dte_service_provider == 'SIIHOMO':
                url = 'https://maullin.sii.cl'
            post = '/cgi_dte/UPL/DTEUpload'
            # port = 443
            # Armo el encabezado por separado para poder debuggear
            headers = {
                'Accept': 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-powerpoint, application/ms-excel, application/msword, */*',
                'Accept-Language': 'es-cl',
                'Accept-Encoding': 'gzip, deflate',
                'User-Agent': 'Mozilla/4.0 (compatible; PROG 1.0; Windows NT 5.0; YComp 5.0.2.4)',
                'Referer': '{}'.format(company_id.website),
                'Connection': 'Keep-Alive',
                'Cache-Control': 'no-cache',
                'Cookie': 'TOKEN={}'.format(token),
            }
            params = collections.OrderedDict()
            params['rutSender'] = signature_d['subject_serial_number'][:8]
            params['dvSender'] = signature_d['subject_serial_number'][-1]
            params['rutCompany'] = company_id.vat[2:-1]
            params['dvCompany'] = company_id.vat[-1]
            file_name = file_name + '.xml'
            params['archivo'] = (file_name,envio_dte,"text/xml")
            multi  = urllib3.filepost.encode_multipart_formdata(params)
            headers.update({'Content-Length': '{}'.format(len(multi[0]))})
            response = pool.request_encode_body('POST', url+post, params, headers)
            retorno = {'sii_xml_response': response.data, 'sii_result': 'NoEnviado','sii_send_ident':''}
            if response.status != 200:
                return retorno
            respuesta_dict = xmltodict.parse(response.data)
            _logger.info("l733-dict respuesta")
            _logger.info(respuesta_dict)
            if respuesta_dict['RECEPCIONDTE']['STATUS'] != '0':
                _logger.info('l736-status no es 0')
                _logger.info(connection_status[respuesta_dict['RECEPCIONDTE']['STATUS']])
            else:
                _logger.info('l796-status es 0')
                _logger.info(respuesta_dict['RECEPCIONDTE']['TRACKID'])
                retorno.update({'sii_result': 'Enviado','sii_send_ident':respuesta_dict['RECEPCIONDTE']['TRACKID']})
            return retorno

    '''
    Funcion para descargar el xml en el sistema local del usuario
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    @api.multi
    def get_xml_file(self):
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=stock.picking\
&field=sii_xml_request&id=%s&filename=demoxml.xml' % (self.id),
            'target': 'self',
        }

    '''
    Funcion para descargar el folio tomando el valor desde la secuencia
    correspondiente al tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_folio(self, rec):
        # saca el folio directamente de la secuencia
        return int(rec.sii_document_number)

    '''
         Se Retorna el CAF que corresponda a la secuencia, independiente del estado
         ya que si se suben 2 CAF y uno está por terminar y se hace un evío masivo
         Deja fuera Los del antiguo CAF, que son válidos aún, porque no se han enviado; y arroja Error
         de que la secuencia no está en el rango del CAF
    '''
    def get_caf_file(self, rec):
        caffiles = rec.picking_type_id.sequence_id.dte_caf_ids
        folio = self.get_folio(rec)
        for caffile in caffiles:
            post = base64.b64decode(caffile.caf_file)
            post = xmltodict.parse(post.replace(
                '<?xml version="1.0"?>','',1))
            folio_inicial = post['AUTORIZACION']['CAF']['DA']['RNG']['D']
            folio_final = post['AUTORIZACION']['CAF']['DA']['RNG']['H']
            if folio in range(int(folio_inicial), (int(folio_final)+1)):
                return post
        if not caffiles:
            raise Warning(_('''There is no CAF file available or in use \
for this Document. Please enable one.'''))

        if folio > folio_final:
            msg = '''El folio de este documento: {} está fuera de rango \
del CAF vigente (desde {} hasta {}). Solicite un nuevo CAF en el sitio \
www.sii.cl'''.format(folio, folio_inicial, folio_final)
            #_logger.info(msg)
            # defino el status como "spent"
            caffile.status = 'spent'
            raise Warning(_(msg))
        return False

    '''
    Funcion para reformateo del vat desde modo Odoo (dos digitos pais sin guion)
    a valor sin puntuacion con guion
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def format_vat(self, value):
        return value[2:10] + '-' + value[10:]


    '''
    Funcion creacion de imagen pdf417 basada en biblioteca elaphe
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def pdf417bc(self, ted):
        _logger.info('Drawing the TED stamp in PDF417')
        bc = barcode(
            'pdf417',
            ted,
            options = dict(
                compact = False,
                eclevel = 5,
                columns = 13,
                rowmult = 2,
                rows = 3
            ),
            margin=20,
            scale=1
        )
        return bc

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def digest(self, data):
        sha1 = hashlib.new('sha1', data)
        return sha1.digest()

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def signrsa(self, MESSAGE, KEY, digst=''):
        KEY = KEY.encode('ascii')
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        _logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            _logger.info("""Signature verified! Returning signature, modulus \
and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64eDigesncode(rsa_m.e)}
        else:
            _logger.info("""Signature verified! Returning signature, modulus, \
exponent. AND DIGEST""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def signmessage(self, MESSAGE, KEY, pubk='', digst=''):
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        _logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            _logger.info("""Signature verified! Returning signature, modulus \
and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e)}
        else:
            _logger.info("""Signature verified! Returning signature, modulus, \
exponent. AND DIGEST""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

    '''
    Definicion de extension de modelo de datos para stock_picking
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-02-01
     @ported : Daniel Santibáñez Polanco (dansanti[at]gmail.com)
    '''
    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together')
    sii_barcode = fields.Char(
        copy=False,
        string=_('SII Barcode'),
        readonly=True,
        help='SII Barcode Name')
    sii_barcode_img = fields.Binary(
        copy=False,
        string=_('SII Barcode Image'),
        help='SII Barcode Image in PDF417 format')
    sii_message = fields.Text(
        string='SII Message',
        copy=False)
    sii_xml_request = fields.Text(
        string='SII XML Request',
        copy=False)
    sii_xml_response = fields.Text(
        string='SII XML Response',
        copy=False)
    sii_send_ident = fields.Text(
        string='SII Send Identification',
        copy=False)
    sii_result = fields.Selection([
        ('', 'n/a'),
        ('NoEnviado', 'No Enviado'),
        ('Enviado', 'Enviado'),
        ('Aceptado', 'Aceptado'),
        ('Rechazado', 'Rechazado'),
        ('Reparo', 'Reparo'),
        ('Proceso', 'Proceso'),
        ('Reenviar', 'Reenviar'),
        ('Anulado', 'Anulado')],
        'Resultado',
        readonly=True,
        states={'draft': [('readonly', False)]},
        copy=False,
        help="SII request result",
        default = '')
    canceled = fields.Boolean(string="Is Canceled?")

    def _acortar_str(self, texto, size=1):
        c = 0
        cadena = ""
        while c < size and c < len(texto):
            cadena += texto[c]
            c += 1
        return cadena

    @api.multi
    def get_barcode(self, rec,  dte_service, inv=False):
        ted = False
        folio = self.get_folio(rec)
        result['TED']['DD']['RE'] = rec.format_vat(rec.company_id.vat)
        result['TED']['DD']['TD'] = 52
        result['TED']['DD']['F']  = folio
        result['TED']['DD']['FE'] = rec.min_date[:10]
        if not rec.partner_id.vat:
            raise UserError(_("Fill Partner VAT"))
        result['TED']['DD']['RR'] = rec.format_vat(rec.partner_id.vat)
        result['TED']['DD']['RSR'] = self._acortar_str(rec.partner_id.name,40)
        result['TED']['DD']['MNT'] = int(round(rec.amount_total))

        for line in rec.pack_operation_product_ids:
            name = line.name or line.product_id.name
            result['TED']['DD']['IT1'] = self._acortar_str(name,40)
            if line.product_id.default_code:
                result['TED']['DD']['IT1'] = self._acortar_str(name.replace('['+line.product_id.default_code+'] ',''),40)
            break
        resultcaf = self.get_caf_file(rec)

        result['TED']['DD']['CAF'] = resultcaf['AUTORIZACION']['CAF']
        dte = result['TED']['DD']
        ddxml = '<DD>'+dicttoxml.dicttoxml(
            dte, root=False, attr_type=False).replace(
            '<key name="@version">1.0</key>','',1).replace(
            '><key name="@version">1.0</key>',' version="1.0">',1).replace(
            '><key name="@algoritmo">SHA1withRSA</key>',
            ' algoritmo="SHA1withRSA">').replace(
            '<key name="#text">','').replace(
            '</key>','').replace('<CAF>','<CAF version="1.0">')+'</DD>'
        ###### con esta funcion fuerzo la conversion a iso-8859-1
        ddxml = rec.convert_encoding(ddxml, 'utf-8')
        # ahora agarro la clave privada y ya tengo los dos elementos
        # que necesito para firmar
        keypriv = (resultcaf['AUTORIZACION']['RSASK']).encode(
            'latin-1').replace('\t','')
        keypub = (resultcaf['AUTORIZACION']['RSAPUBK']).encode(
            'latin-1').replace('\t','')
        #####
        ## antes de firmar, formatear
        root = etree.XML( ddxml )
        # funcion de remover indents en el ted y formateo xml
        # ddxml = self.remove_indents(
        #     (etree.tostring(root, pretty_print=True)))
        ##
        ddxml = etree.tostring(root)
        timestamp = self.time_stamp()
        ddxml = ddxml.replace('2014-04-24T12:02:20', timestamp)
        frmt = rec.signmessage(ddxml, keypriv, keypub)['firma']
        ted = ('''<TED version="1.0">{}<FRMT algoritmo="SHA1withRSA">{}\
</FRMT></TED>''').format(ddxml, frmt)
        _logger.info(ted)
        root = etree.XML(ted)
        rec.sii_barcode = ted
        image = False
        if ted:
            barcodefile = StringIO()
            image = rec.pdf417bc(ted)
            image.save(barcodefile,'PNG')
            data = barcodefile.getvalue()
            rec.sii_barcode_img = base64.b64encode(data)
        ted  = ted + '<TmstFirma>{}</TmstFirma>'.format(timestamp)
        return ted

    @api.multi
    def do_dte_send_picking(self, n_atencion=False):
        cant_doc_batch = 0
        DTEs = {}
        count = 0
        company_id = False
        for rec in self.with_context(lang='es_CL'):
            total = 0
            subtotal = 0
            try:
                signature_d = self.get_digital_signature(rec.company_id)
            except:
                raise Warning(_('''There is no Signer Person with an \
            authorized signature for you in the system. Please make sure that \
            'user_signature_key' module has been installed and enable a digital \
            signature, for you or make the signer to authorize you to use his \
            signature.'''))
            certp = signature_d['cert'].replace(
                BC, '').replace(EC, '').replace('\n', '')
            cant_doc_batch = cant_doc_batch + 1
            dte_service = rec.company_id.dte_service_provider
            line_number = 1
            picking_lines = []
            no_product = False
            lines = rec.pack_operation_product_ids
            inv = False
            lin_dr = 1
            dr_lines = []
            if inv and 'global_discount' in inv and inv.global_discount:# or inv.global_rec:
                dr_line = {}
                dr_line = collections.OrderedDict()
                dr_line['NroLinDR'] = lin_dr
                dr_line['TpoMov'] = 'D'
                if inv.global_discount_detail:
                    dr_line['GlosaDR'] = inv.global_discount_detail
                disc_type = "%"
                ValorDR = round((inv.global_discount * 100),2)
                if inv.global_discount_type == "amount":
                    disc_type = "$"
                    ValorDR = round(inv.global_discount)
                dr_line['TpoValor'] = disc_type
                dr_line['ValorDR'] = ValorDR
                dr_lines.extend([{'DscRcgGlobal':dr_line}])
            lin_ref = 1
            ref_lines = []
            TasaIVA = "19.00"
            folio = self.get_folio(rec)
            if dte_service == 'SIIHOMO' and isinstance(n_atencion, unicode):
                ref_line = {}
                ref_line = collections.OrderedDict()
                ref_line['NroLinRef'] = lin_ref
                count = count +1
                ref_line['TpoDocRef'] = "SET"
                ref_line['FolioRef'] = folio
                ref_line['FchRef'] = datetime.strftime(datetime.now(), '%Y-%m-%d')
                ref_line['RazonRef'] = "CASO "+n_atencion+"-" + str(rec.sii_batch_number)
                lin_ref = 2
                ref_lines.extend([{'Referencia':ref_line}])
            for ref in rec.reference:
                if ref.sii_referencia_TpoDocRef in ['33','34']:#@TODO Mejorar Búsqueda
                    inv = self.env["account.invoice"].search([('sii_document_number','=',str(ref.origen))])
                ref_line = {}
                ref_line = collections.OrderedDict()
                ref_line['NroLinRef'] = lin_ref
                if  ref.sii_referencia_TpoDocRef:
                    ref_line['TpoDocRef'] = ref.sii_referencia_TpoDocRef
                    ref_line['FolioRef'] = ref.origen
                    ref_line['FchRef'] = datetime.strftime(datetime.now(), '%Y-%m-%d')
                    if ref.date:
                        ref_line['FchRef'] = ref.date
                ref_lines.extend([{'Referencia':ref_line}])
            for line in lines :
                if line.product_id.default_code == 'NO_PRODUCT':
                    no_product = True
                lines = collections.OrderedDict()
                lines['NroLinDet'] = line_number
                if line.product_id.default_code and not no_product:
                    lines['CdgItem'] = collections.OrderedDict()
                    lines['CdgItem']['TpoCodigo'] = 'INT1'
                    lines['CdgItem']['VlrCodigo'] = line.product_id.default_code
                name = line.name or line.product_id.name
                #name = line.product_id.name
                lines['NmbItem'] = self._acortar_str(name,80)
                if line.product_id.default_code:
                    lines['NmbItem'] = self._acortar_str(name.replace('['+line.product_id.default_code+'] ',''),80)
                if not 'qty_done' in line:
                    raise UserError(_('Must add some quantity moved!'))
                else :
                    qty = line.qty_done
                    uom = line.product_uom_id.name[:4]
                lines['QtyItem'] = 1
                if qty > 0:
                    lines['QtyItem'] = qty
                else:
                    raise UserError("NO puede ser menor que 0")
                lines['UnmdItem'] = uom
                if line.price_unit > 0:
                    lines['PrcItem'] = line.price_unit
                if line.discount > 0: # SSe asume de que siempre en odoo el decuento viene en % para las l´ineas
                    lines['DescuentoPct'] = line.discount
                    lines['DescuentoMonto'] = int(round((((line.discount / 100) * line.price_unit)* qty)))
                lines['MontoItem'] = int(round(line.subtotal))
                if line.operation_line_tax_ids:
                    for t in line.operation_line_tax_ids:
                        if t.amount > 0: #@TODO definir método para encntrar iva comun
                            TasaIVA = t.amount
                line_number += 1
                picking_lines.extend([{'Detalle': lines}])
            ted1 = self.get_barcode(rec, dte_service,inv)
            dte = collections.OrderedDict()
            dte1 = collections.OrderedDict()
            giros_emisor = []
            for turn in rec.company_id.company_activities_ids:
                giros_emisor.extend([{'Acteco': turn.code}])
            dte['Encabezado'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc']['TipoDTE'] = 52
            dte['Encabezado']['IdDoc']['Folio'] = folio
            dte['Encabezado']['IdDoc']['FchEmis'] = rec.min_date[:10]
            if rec.transport_type and rec.transport_type != "0":
                dte['Encabezado']['IdDoc']['TipoDespacho'] = rec.transport_type
            dte['Encabezado']['IdDoc']['IndTraslado'] = rec.move_reason
            dte['Encabezado']['Emisor'] = collections.OrderedDict()
            dte['Encabezado']['Emisor']['RUTEmisor'] = self.format_vat(rec.company_id.vat)
            dte['Encabezado']['Emisor']['RznSoc'] = rec.company_id.partner_id.name
            dte['Encabezado']['Emisor']['GiroEmis'] = rec.turn_issuer.name[:80]
            dte['Encabezado']['Emisor']['Telefono'] = rec.company_id.phone or ''
            dte['Encabezado']['Emisor']['CorreoEmisor'] = rec.company_id.dte_email
            dte['Encabezado']['Emisor']['item'] = giros_emisor # giros de la compañia - codigos
            # todo: <CdgSIISucur>077063816</CdgSIISucur> codigo de sucursal
            dte['Encabezado']['Emisor']['DirOrigen'] = rec.company_id.street
            dte['Encabezado']['Emisor']['CmnaOrigen'] = rec.company_id.state_id.name
            dte['Encabezado']['Emisor']['CiudadOrigen'] = rec.company_id.city
            dte['Encabezado']['Receptor'] = collections.OrderedDict()
            dte['Encabezado']['Receptor']['RUTRecep'] = self.format_vat(rec.partner_id.vat)
            dte['Encabezado']['Receptor']['RznSocRecep'] = rec.partner_id.name
            if not rec.partner_turn:
                raise UserError(_('Seleccione giro del asociado'))
            dte['Encabezado']['Receptor']['GiroRecep'] = rec.partner_turn.name[:40]
            dte['Encabezado']['Receptor']['DirRecep'] = rec.partner_id.street + ' ' + (rec.partner_id.street2 or '')
            dte['Encabezado']['Receptor']['CmnaRecep'] = rec.partner_id.state_id.name
            dte['Encabezado']['Receptor']['CiudadRecep'] = rec.partner_id.city
            dte['Encabezado']['Transporte'] = collections.OrderedDict()
            if rec.patente:
                dte['Encabezado']['Transporte']['Patente'] = rec.patente[:8]
            elif rec.vehicle:
                dte['Encabezado']['Transporte']['Patente'] = rec.vehicle.matricula or ''
            if rec.transport_type in ['2','3'] and rec.chofer:
                if not rec.chofer.vat:
                    raise UserError("Debe llenar los datos del chofer")
                if rec.transport_type == '2':
                    dte['Encabezado']['Transporte']['RUTTrans'] = self.format_vat(rec.company_id.vat)
                else:
                    if not rec.carrier_id.partner_id.vat:
                        raise UserError("Debe especificar el RUT del transportista, en su ficha de partner")
                    dte['Encabezado']['Transporte']['RUTTrans'] = self.format_vat(rec.carrier_id.partner_id.vat)
                if rec.chofer:
                    dte['Encabezado']['Transporte']['Chofer'] = collections.OrderedDict()
                    dte['Encabezado']['Transporte']['Chofer']['RUTChofer'] = self.format_vat(rec.chofer.vat)
                    dte['Encabezado']['Transporte']['Chofer']['NombreChofer'] = rec.chofer.name[:30]
            dte['Encabezado']['Transporte']['DirDest'] = (rec.partner_id.street or '')+ ' '+ (rec.partner_id.street2 or '')
            dte['Encabezado']['Transporte']['CmnaDest'] = rec.partner_id.state_id.name or ''
            dte['Encabezado']['Transporte']['CiudadDest'] = rec.partner_id.city or ''
            #@TODO SUb Area Aduana
            dte['Encabezado']['Totales'] = collections.OrderedDict()
            #@TODO aplicar decuentos
            dte['Encabezado']['Totales']['MntNeto'] = int(round(rec.amount_untaxed, 0))
            dte['Encabezado']['Totales']['TasaIVA'] = TasaIVA
            dte['Encabezado']['Totales']['IVA'] = int(round(rec.amount_tax, 0))
            dte['Encabezado']['Totales']['MntTotal'] = int(round(rec.amount_total, 0))
            dte['item'] = picking_lines
            dte['drLines'] = dr_lines
            dte['refs'] = ref_lines
            doc_id_number = "F{}T{}".format(
                folio, '52')
            doc_id = '<Documento ID="{}">'.format(doc_id_number)
            if dte_service in ['SII', 'SIIHOMO']:
                dte['TEDd'] = 'TEDTEDTED'
            dte1['Documento ID'] = dte
            xml = dicttoxml.dicttoxml(
                dte1, root=False, attr_type=False).replace('<item>','').replace('</item>','').replace('<refs>','').replace('</refs>','').replace('<drLines>','').replace('</drLines>','')
            if dte_service in ['SII', 'SIIHOMO']:
                xml = xml.replace('<TEDd>TEDTEDTED</TEDd>', ted1)
            root = etree.XML( xml )
            xml_pret = etree.tostring(root, pretty_print=True).replace(
'<Documento_ID>', doc_id).replace('</Documento_ID>', '</Documento>')
            if dte_service in ['SII', 'SIIHOMO']:
                envelope_efact = self.convert_encoding(xml_pret, 'ISO-8859-1')
                envelope_efact = self.create_template_doc(envelope_efact)
                einvoice = self.sign_full_xml(
                    envelope_efact, signature_d['priv_key'],
                    self.split_cert(certp), doc_id_number)
                DTEs.update( {rec.id: einvoice})
                if not company_id:
                    company_id = rec.company_id
                elif company_id.id != rec.company_id.id:
                    raise UserError("Está combinando compañías")
                company_id = rec.company_id
        file_name = 'T52'
        dtes=""
        SubTotDTE = ''
        resol_data = self.get_resolution_data(company_id)
        signature_d = self.get_digital_signature(company_id)
        RUTEmisor = self.format_vat(company_id.vat)
        NroDte = 0
        for rec_id,  documento in DTEs.iteritems():
            dtes += '\n'+documento
            doc = self.env['stock.picking'].browse(rec_id)
            doc.sii_xml_request = documento
            NroDte += 1
            file_name += 'F' + str(int(doc.sii_document_number))
        SubTotDTE += '<SubTotDTE>\n<TpoDTE>52</TpoDTE>\n<NroDTE>'+str(NroDte)+'</NroDTE>\n</SubTotDTE>\n'
        RUTRecep = "60803000-K" # RUT SII
        dtes = self.create_template_envio( RUTEmisor, RUTRecep,
            resol_data['dte_resolution_date'],
            resol_data['dte_resolution_number'],
            self.time_stamp(), dtes, signature_d,SubTotDTE )
        envio_dte  = self.create_template_env(dtes)
        envio_dte = self.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            'SetDoc', 'env')
        self.xml_validator(envio_dte, 'env')
        result = self.send_xml_file(envio_dte, file_name, company_id)
        for rec in self:
            rec.write({'sii_xml_response':result['sii_xml_response'], 'sii_send_ident':result['sii_send_ident'], 'sii_result': result['sii_result']})
            last = rec
        rec.write({'sii_xml_request':envio_dte})
        return {'warning':{'title':_('¡Enviado!'), 'message': _('El Documento ha sido enviado, espere al menos 10s para consultar estado')}}

    def _get_send_status(self, track_id, signature_d,token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws'
        _server = SOAPProxy(url, ns)
        rut = self.format_vat(self.company_id.vat)
        respuesta = _server.getEstUp(rut[:8], str(rut[-1]),track_id,token)
        self.sii_message = respuesta
        _logger.info(respuesta)
        resp = xmltodict.parse(respuesta)
        status = False
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "-11":
            status =  {'warning':{'title':_('Error -11'), 'message': _("Error -11: Espere a que sea aceptado por el SII, intente en 5s más")}}
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.sii_result = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.sii_result = "Rechazado"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.sii_result = "Rechazado"
            status = {'warning':{'title':_('Error RCT'), 'message': _(resp['SII:RESPUESTA']['GLOSA'])}}
        return status

    def _get_dte_status(self, signature_d, token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws'
        _server = SOAPProxy(url, ns)
        receptor = self.format_vat(self.partner_id.vat)
        min_date = datetime.strptime(self.min_date[:10], "%Y-%m-%d").strftime("%d-%m-%Y")
        total = str(int(round(self.amount_total,0)))
        sii_code = str(self.picking_type_id.sii_document_class_id.sii_code)
        respuesta = _server.getEstDte(signature_d['subject_serial_number'][:8], str(signature_d['subject_serial_number'][-1]),
                self.company_id.vat[2:-1],self.company_id.vat[-1], receptor[:8],receptor[2:-1], sii_code, str(self.sii_document_number),
                min_date, total,token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == '2':
        	status = {'warning':{'title':_("Error code: 2"), 'message': _(resp['SII:RESPUESTA']['SII:RESP_HDR']['GLOSA'])}}
        	return status
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.sii_result = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.sii_result = "Rechazado"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['REPARO'] == "1":
                self.sii_result = "Reparo"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.sii_result = "Rechazado"

    @api.multi
    def ask_for_dte_status(self):
        try:
            signature_d = self.get_digital_signature_pem(
                self.company_id)
            seed = self.get_seed(self.company_id)
            template_string = self.create_template_seed(seed)
            seed_firmado = self.sign_seed(
                template_string, signature_d['priv_key'],
                signature_d['cert'])
            token = self.get_token(seed_firmado,self.company_id)
        except:
            raise Warning(connection_status[response.e])
        xml_response = xmltodict.parse(self.sii_xml_response)
        if self.sii_result == 'Enviado':
            status = self._get_send_status(self.sii_send_ident, signature_d, token)
            if self.sii_result != 'Proceso':
                return status
        return self._get_dte_status(signature_d, token)
