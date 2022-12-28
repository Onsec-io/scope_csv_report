FROM ruby:3-alpine

RUN gem install public_suffix:5.0.1 && adduser --uid 1000 -D scope

USER scope

COPY scripts /opt/scripts

CMD ["ruby", "/opt/scripts/run.rb"]

