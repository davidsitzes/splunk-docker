This directory contains platform CSS files that are loaded in minified css mode. This static linking guards against
incompatibilities in the minified JS and CSS for upgrades or downgrades of the Splunk platform. The directory structure
matches against the platform URIs to encompass both CSS from Mr. Sparkle (/static/css/...) as well as
CSS from bundled applications such as the Search App (/static/app/...).
Therefore, relative to this directory:
./build/bootstrap.min.css -> /static/css/build/bootstrap.min.css
./pages/dashboard-simple-bootstrap.min.css -> /static/css/pages/dashboard-simple-bootstrap.min.css
./app/search/dashboard.css -> /static/app/search/dashboard.css
