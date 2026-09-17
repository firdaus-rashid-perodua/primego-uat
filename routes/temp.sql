             AND AC2.VML_MANUFACTURING_CODE IN (
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ'
                      WHEN 'ALZA' THEN 'BP5HZ'
                      WHEN 'AXIA' THEN 'CG1XZ'
                      WHEN 'BEZZA' THEN 'AQ1GZ2'
                      WHEN 'ARUZ' THEN 'W5XZ2'
                      WHEN 'ATIVA' THEN 'U1XZ'
                      WHEN 'TRAZ' THEN 'Y5XZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD3GZ1'
                      WHEN 'ALZA' THEN 'BP5VZ'
                      WHEN 'AXIA' THEN 'CG1SZ'
                      WHEN 'BEZZA' THEN 'AQ1GX2'
                      WHEN 'ARUZ' THEN 'W5VZ1'
                      WHEN 'ATIVA' THEN 'U1HZ'
                      WHEN 'TRAZ' THEN 'Y5HZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5XZ'
                      WHEN 'ALZA' THEN 'BP5XZ'
                      WHEN 'AXIA' THEN 'CG1GZ'
                      WHEN 'BEZZA' THEN 'AQ3XZ1'
                      WHEN 'ARUZ' THEN 'W5VZ2'
                      WHEN 'ATIVA' THEN 'U1VZ'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      WHEN 'AXIA' THEN 'CG1VZ'
                      WHEN 'BEZZA' THEN 'AQ3VZ1'
                      ELSE 'UNKNOWN'
                  END,
                  CASE t.[MODEL]
                      WHEN 'MYVI' THEN 'BD5VZ'
                      ELSE 'UNKNOWN'
                  END
              )