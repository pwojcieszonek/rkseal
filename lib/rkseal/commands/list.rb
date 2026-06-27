# frozen_string_literal: true

require "json"
require "time"

module RKSeal
  module Commands
    # Orchestrates the `rkseal list [namespace]` flow.
    #
    # Lists the SealedSecret CRD objects in the cluster (all namespaces, or a
    # single one) as a kubectl-style table. Strictly read-only and metadata-only:
    # it prints solely each object's namespace, name, derived scope, and age --
    # NEVER any part of `spec.encryptedData` (not even its keys). No editor, no
    # RAM workspace, no file is written.
    #
    # @example all namespaces
    #   puts RKSeal::Commands::List.new.call
    # @example one namespace
    #   puts RKSeal::Commands::List.new(namespace: "app").call
    class List
      # @return [String, nil] the namespace filter, or nil for all namespaces.
      attr_reader :namespace

      # Column headers, in display order.
      HEADERS = %w[NAMESPACE NAME SCOPE AGE].freeze

      # Scope symbol -> the dashed display label shown in the SCOPE column.
      SCOPE_LABELS = {
        strict: "strict",
        namespace_wide: "namespace-wide",
        cluster_wide: "cluster-wide"
      }.freeze

      # @param namespace [String, nil] limit to this namespace; nil lists all.
      # @param kubectl [RKSeal::Kubectl] cluster adapter (read only).
      # @param now [Time] clock used to compute AGE (injectable for tests).
      def initialize(namespace: nil, kubectl: Kubectl.new, now: Time.now)
        @namespace = namespace
        @kubectl = kubectl
        @now = now
      end

      # Run the list flow: read the SealedSecrets and render the table.
      #
      # Side effects: a single read-only `kubectl get sealedsecret`. No editor,
      # no workspace, no file write.
      #
      # @return [String] the table (or a friendly empty-list message) to print.
      # @raise [RKSeal::CommandError] kubectl failed.
      def call
        @kubectl.ensure_available!
        items = parse_items(@kubectl.list_sealedsecrets(namespace: @namespace))
        return empty_message if items.empty?

        render_table(items.map { |item| row_for(item) })
      end

      private

      def parse_items(json)
        doc = JSON.parse(json)
        items = doc.is_a?(Hash) ? doc["items"] : nil
        items.is_a?(Array) ? items : []
      rescue JSON::ParserError => e
        raise CommandError.new("kubectl did not return valid JSON: #{e.message}",
                               command: "kubectl get sealedsecret")
      end

      # Build a single table row from one SealedSecret. Reads ONLY metadata --
      # `spec` is never touched, so no encrypted material can leak.
      def row_for(item)
        metadata = item["metadata"] || {}
        [
          metadata["namespace"].to_s,
          metadata["name"].to_s,
          SCOPE_LABELS.fetch(Secret.scope_from_sealed_json(item)),
          age_for(metadata["creationTimestamp"])
        ]
      end

      # kubectl-style compact age (e.g. "3d", "5h", "2m", "10s") from an RFC3339
      # creationTimestamp. Unknown/unparseable -> "<unknown>".
      def age_for(timestamp)
        return "<unknown>" if timestamp.nil? || timestamp.to_s.empty?

        seconds = (@now - Time.parse(timestamp.to_s)).to_i
        humanize_age(seconds)
      rescue ArgumentError
        "<unknown>"
      end

      def humanize_age(seconds)
        seconds = 0 if seconds.negative?
        case seconds
        when 0...60 then "#{seconds}s"
        when 60...3600 then "#{seconds / 60}m"
        when 3600...86_400 then "#{seconds / 3600}h"
        else "#{seconds / 86_400}d"
        end
      end

      # Render rows as a left-aligned, space-padded table with a header line,
      # matching kubectl's `get` output style.
      def render_table(rows)
        widths = column_widths(rows)
        [HEADERS, *rows].map { |row| format_row(row, widths) }.join("\n")
      end

      def column_widths(rows)
        HEADERS.each_index.map do |col|
          [HEADERS[col], *rows.map { |row| row[col] }].map(&:length).max
        end
      end

      # Pad every cell but the last to its column width (trailing column is left
      # un-padded so there is no trailing whitespace), joined by three spaces.
      def format_row(row, widths)
        row.each_with_index.map do |cell, col|
          col == row.length - 1 ? cell : cell.ljust(widths[col])
        end.join("   ").rstrip
      end

      def empty_message
        return "No SealedSecrets found." if @namespace.nil?

        "No SealedSecrets found in namespace #{@namespace.inspect}."
      end
    end
  end
end
