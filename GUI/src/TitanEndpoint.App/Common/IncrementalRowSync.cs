using System.Collections.ObjectModel;
using TitanEndpoint.Core.Json;

namespace TitanEndpoint.App.Common;

/// <summary>
/// Appends only genuinely new records (by monotonic SequenceId) from a tailer's
/// ring-buffer snapshot into a UI-bound ObservableCollection, so a live table
/// never re-renders thousands of unchanged rows every tick.
/// </summary>
public sealed class IncrementalRowSync<TRow>
{
    private readonly ObservableCollection<TRow> _target;
    private readonly Func<JsonRecord, bool> _filter;
    private readonly Func<JsonRecord, TRow> _map;
    private readonly int _maxRows;
    private long _lastSeq = -1;

    public IncrementalRowSync(ObservableCollection<TRow> target, int maxRows, Func<JsonRecord, TRow> map, Func<JsonRecord, bool>? filter = null)
    {
        _target = target;
        _maxRows = maxRows;
        _map = map;
        _filter = filter ?? (_ => true);
    }

    public void Sync(JsonRecord[] snapshot)
    {
        if (snapshot.Length == 0) return;

        // If our cursor fell out of the ring buffer entirely, resync from scratch to stay consistent.
        if (_lastSeq >= 0 && snapshot[0].SequenceId > _lastSeq + 1 && snapshot[^1].SequenceId - snapshot.Length + 1 > _lastSeq)
        {
            _target.Clear();
            _lastSeq = -1;
        }

        foreach (var record in snapshot)
        {
            if (record.SequenceId <= _lastSeq) continue;
            if (_filter(record))
            {
                _target.Add(_map(record));
                while (_target.Count > _maxRows) _target.RemoveAt(0);
            }
            _lastSeq = record.SequenceId;
        }
    }
}
