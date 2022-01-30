DROP TABLE IF EXISTS admin_auth;
DROP TABLE IF EXISTS employee_info;

CREATE TABLE IF NOT EXISTS admin_auth(username TEXT NOT NULL,
                                    password TEXT not null );

INSERT INTO admin_auth (username,password) VALUES ('admin', 'admin');

CREATE TABLE IF NOT EXISTS employee_info(
            employee_id INTEGER PRIMARY KEY,
            employee_name TEXT not null ,
            gender TEXT not null,
            email TEXT not null,
            address TEXT not null,
            academic_qualification TEXT not null,
            username TEXT not null UNIQUE,
            password TEXT not null);

