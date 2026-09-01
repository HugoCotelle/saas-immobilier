{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python313
    python313Packages.flask
    python313Packages.flask-cors
    python313Packages.pyjwt
    python313Packages.psycopg2
    python313Packages.python-dotenv
    python313Packages.gunicorn
  ];
}
