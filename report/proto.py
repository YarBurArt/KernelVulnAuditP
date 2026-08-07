import json

from core import dict_to_display_rows

try:
    import streamlit as st  # type: ignore[import-not-found]
except ImportError:
    st = None  # type: ignore


def generate_report(raw_d):
    assert st is not None
    st.set_page_config(page_title="Kernel Report", layout="wide")

    st.title("System scan report")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Started", raw_d["started"])
    c2.metric("Completed", raw_d["complated"])
    c3.metric("Kernel", raw_d["kernel_version"])
    c4.metric("From", raw_d["distribution"])
    c5.metric("Latest", raw_d["latest_version"])

    with st.expander(f"KEV stats ({len(raw_d['kev_data'])})"):
        if raw_d["kev_data"]:
            # table fix
            st.markdown(
                """
                <style>
                    .stTable { overflow-x: auto; }
                    table td { white-space: normal !important; }
                    td { max-width: 400pt; min-width: 100pt; }
                </style>
            """,
                unsafe_allow_html=True,
            )
            # print(data["kev_data"])
            st.table(dict_to_display_rows(raw_d["kev_data"]))
        else:
            st.info("No CVE data available")

    st.subheader("Execution logs")
    for run in raw_d["runs"]:
        with st.expander(f"Run {run['id']} - [{run['status']}]"):
            st.write(run["description"])
            col_out, col_err = st.columns(2)
            col_out.text_area(
                "STDOUT", run["stdout"], height=100, key=f"out_{run['id']}"
            )
            col_err.write("STDERR")
            if run["stderr"]:
                col_err.error(run["stderr"])
            else:
                col_err.write("No errors")


if __name__ == "__main__":
    try:
        with open("report_data.json", "r") as f:
            data = json.load(f)
            generate_report(data)
    except FileNotFoundError as e:
        st.error(e)
