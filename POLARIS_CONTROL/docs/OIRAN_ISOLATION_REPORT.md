# Isolation report

POLARIS Control is a separate Git repository, workspace, listener, configuration, and log boundary. It uses port 49153; OIRAN remains on port 49152. No OIRAN source, dataset, or API is a build dependency. The integration contract carries only scenario/capture references and never decoded or correlated claims.
