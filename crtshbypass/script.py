import requests
import psycopg2
import logging as log

class CrtSh:
    domain = None
    def __init__(self, domain):
        self.domain = domain
        
    def StartScan(self):
        result = self.ExtractFromDb()
        if not(result):
            log.debug('Extract from DB Failed')
            result = self.ExtractFromWeb()
        return result

    def ExtractFromWeb(self):
        subdomains = []
        req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=self.domain))
        if req.status_code != 200:
            return []
        for item in req.json():
            subdomains.extend(item['name_value'].split('\n'))
        return sorted(set(subdomains))

    def ExtractFromDb(self):
        dbname = 'certwatch'
        user = 'guest'
        password = ''
        host = 'crt.sh'
        port = '5432' 
        sql_query = f"""
        WITH ci AS (
        SELECT min(sub.CERTIFICATE_ID) ID,
           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
           x509_commonName(sub.CERTIFICATE) COMMON_NAME,
           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
           encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER,
           count(sub.CERTIFICATE_ID)::bigint RESULT_COUNT
        FROM (SELECT cai.*
                  FROM certificate_and_identities cai
                  WHERE plainto_tsquery('certwatch', '{self.domain}') @@ identities(cai.CERTIFICATE)
                      AND cai.NAME_VALUE ILIKE concat('%', '{self.domain}', '%')
             ) sub
        GROUP BY sub.CERTIFICATE
        )
        SELECT ci.ISSUER_CA_ID,
           ca.NAME ISSUER_NAME,
           ci.COMMON_NAME,
           array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
           ci.ID ID,
           le.ENTRY_TIMESTAMP,
           ci.NOT_BEFORE,
           ci.NOT_AFTER,
           ci.SERIAL_NUMBER,
           ci.RESULT_COUNT
        FROM ci
            LEFT JOIN LATERAL (
                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.ID
            ) le ON TRUE,
         ca
        WHERE ci.ISSUER_CA_ID = ca.ID
        ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;
        """

        try:
            conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
            conn.set_session(autocommit=True, readonly=True)
        except psycopg2.Error as e:
            log.warning(f"Error in connecting to crt.sh database {e}")
            return

        cur = conn.cursor()

        try:
            cur.execute(sql_query)
            rows = cur.fetchall()
            subdomains = []
            for row in rows:
                subdomains.extend(row[3].split('\n'))
            return sorted(set(subdomains))


        except psycopg2.Error as e:
            log.warning(f"Error in making query to crt.sh {e}")

        finally:
            cur.close()
            conn.close()

if __name__ == '__main__':
    log.basicConfig(level=log.DEBUG, format="%(asctime)s %(message)s")
    crtsh = CrtSh("tesla.com")
    result = crtsh.ExtractFromDb()
    if not(result):
        log.debug('Extract from DB Failed')
        result = crtsh.ExtractFromWeb()
    print(result)